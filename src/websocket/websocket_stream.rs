use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::config::WebsocketPingType;
use crate::util::allocate_vec;

const READ_BUFFER_SIZE: usize = 32 * 1024;
const WRITE_BUFFER_SIZE: usize = 32 * 1024;
const MAX_CONTROL_PAYLOAD_SIZE: usize = 125;

pub struct WebsocketStream {
    stream: Box<dyn AsyncStream>,
    is_client: bool,
    ping_type: WebsocketPingType,
    pending_initial_data: bool,

    read_state: ReadState,
    read_frame_final: bool,
    read_frame_masked: bool,
    read_frame_opcode: OpCode,
    read_frame_length: u64,
    read_frame_mask: [u8; 4],
    read_frame_mask_offset: usize,
    fragmented_message: Option<OpCode>,
    text_utf8_pending: [u8; 3],
    text_utf8_pending_len: usize,
    error_close_code: u16,

    unprocessed_buf: Box<[u8]>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,

    write_frame: Box<[u8]>,
    write_frame_start_offset: usize,
    write_frame_end_offset: usize,

    control_data: Box<[u8]>,
    control_data_size: usize,
    pending_control: Option<OpCode>,
    control_flush_pending: bool,
    close_received: bool,
    close_sent: bool,
    terminal_error: Option<String>,
    read_closed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ReadState {
    Init,
    ReadLength { length_bytes_len: usize },
    ReadMask,
    ReadDataContent,
    ReadControlContent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpCode {
    Continue,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Unknown(u8),
}

impl OpCode {
    pub fn from(code: u8) -> Self {
        match code {
            0 => OpCode::Continue,
            1 => OpCode::Text,
            2 => OpCode::Binary,
            8 => OpCode::Close,
            9 => OpCode::Ping,
            10 => OpCode::Pong,
            _ => OpCode::Unknown(code),
        }
    }
}

impl WebsocketStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        is_client: bool,
        ping_type: WebsocketPingType,
        unprocessed_data: &[u8],
    ) -> Self {
        debug_assert!(unprocessed_data.len() <= READ_BUFFER_SIZE);
        let mut unprocessed_buf = allocate_vec(READ_BUFFER_SIZE).into_boxed_slice();
        let mut unprocessed_end_offset = 0;
        let write_frame = allocate_vec(WRITE_BUFFER_SIZE).into_boxed_slice();
        let control_data = allocate_vec(MAX_CONTROL_PAYLOAD_SIZE).into_boxed_slice();

        let pending_initial_data = if !unprocessed_data.is_empty() {
            unprocessed_buf[0..unprocessed_data.len()].copy_from_slice(unprocessed_data);
            unprocessed_end_offset = unprocessed_data.len();
            true
        } else {
            false
        };

        Self {
            stream,
            is_client,
            ping_type,
            pending_initial_data,
            read_state: ReadState::Init,
            read_frame_final: true,
            read_frame_masked: false,
            read_frame_opcode: OpCode::Unknown(99),
            read_frame_length: 0,
            read_frame_mask: [0u8; 4],
            read_frame_mask_offset: 0,
            fragmented_message: None,
            text_utf8_pending: [0; 3],
            text_utf8_pending_len: 0,
            error_close_code: 1002,
            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset,
            write_frame,
            write_frame_start_offset: 0,
            write_frame_end_offset: 0,
            control_data,
            control_data_size: 0,
            pending_control: None,
            control_flush_pending: false,
            close_received: false,
            close_sent: false,
            terminal_error: None,
            read_closed: false,
        }
    }

    fn step_init(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < 2 {
            return Ok(());
        }

        let first = self.unprocessed_buf[self.unprocessed_start_offset];
        let second = self.unprocessed_buf[self.unprocessed_start_offset + 1];
        self.unprocessed_start_offset += 2;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.read_frame_final = first & 0x80 != 0;
        if first & 0x70 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame uses reserved bits without a negotiated extension",
            ));
        }

        self.read_frame_masked = second & 0x80 != 0;

        // Client-to-server frames must be masked, while server-to-client frames must not be.
        if self.is_client == self.read_frame_masked {
            let message = if self.is_client {
                "server frame was masked"
            } else {
                "client frame was not masked"
            };
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            ));
        }

        self.read_frame_opcode = OpCode::from(first & 0x0f);
        self.read_frame_mask_offset = 0;

        match self.read_frame_opcode {
            OpCode::Unknown(code) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown or reserved websocket opcode ({code:#x})"),
                ));
            }
            OpCode::Close | OpCode::Ping | OpCode::Pong => {
                if !self.read_frame_final {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "control frame must not be fragmented",
                    ));
                }
            }
            OpCode::Continue => {
                if self.fragmented_message.is_none() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "continuation frame without an open fragmented message",
                    ));
                }
            }
            OpCode::Text | OpCode::Binary => {
                if self.fragmented_message.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "new data frame while a fragmented message is open",
                    ));
                }
                if !self.read_frame_final {
                    self.fragmented_message = Some(self.read_frame_opcode);
                }
            }
        }

        let length = second & 0x7f;
        if matches!(
            self.read_frame_opcode,
            OpCode::Close | OpCode::Ping | OpCode::Pong
        ) && length > 125
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "control frame payload exceeds 125 bytes",
            ));
        }

        // We don't bother checking max length when it's <= 125,
        // so we do the check in ReadLength.
        if length == 126 {
            self.read_state = ReadState::ReadLength {
                length_bytes_len: 2,
            };
            self.step_read_length(cx, buf, 2)
        } else if length == 127 {
            self.read_state = ReadState::ReadLength {
                length_bytes_len: 8,
            };
            self.step_read_length(cx, buf, 8)
        } else {
            self.read_frame_length = length as u64;
            if self.read_frame_masked {
                self.read_state = ReadState::ReadMask;
                self.step_read_mask(cx, buf)
            } else {
                self.step_check_content(cx, buf)
            }
        }
    }

    fn step_read_length(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        length_bytes_len: usize,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < length_bytes_len {
            return Ok(());
        }

        let length_bytes = &self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + length_bytes_len];
        self.unprocessed_start_offset += length_bytes_len;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        let mut length = 0u64;
        for b in length_bytes {
            length = (length << 8) | (*b as u64);
        }
        self.read_frame_length = length;

        if length_bytes_len == 2 && self.read_frame_length < 126 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "non-canonical 16-bit websocket frame length",
            ));
        }
        if length_bytes_len == 8 && self.read_frame_length < 65536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "non-canonical 64-bit websocket frame length",
            ));
        }
        if self.read_frame_length > 0x7fff_ffff_ffff_ffff {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid frame length ({})", self.read_frame_length),
            ));
        }

        if self.read_frame_masked {
            self.read_state = ReadState::ReadMask;
            self.step_read_mask(cx, buf)
        } else {
            self.step_check_content(cx, buf)
        }
    }

    fn step_read_mask(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < 4 {
            return Ok(());
        }

        let mask_bytes =
            &self.unprocessed_buf[self.unprocessed_start_offset..self.unprocessed_start_offset + 4];
        self.read_frame_mask.copy_from_slice(mask_bytes);

        self.unprocessed_start_offset += 4;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.step_check_content(cx, buf)
    }

    fn step_check_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        match self.read_frame_opcode {
            OpCode::Text | OpCode::Binary | OpCode::Continue => {
                if self.read_frame_length == 0 {
                    self.finish_data_frame()?;
                    self.read_state = ReadState::Init;
                    self.step_init(cx, buf)
                } else {
                    self.read_state = ReadState::ReadDataContent;
                    self.step_read_data_content(cx, buf)
                }
            }
            OpCode::Ping | OpCode::Pong | OpCode::Close => {
                self.control_data_size = 0;
                if self.read_frame_length == 0 {
                    self.finish_control_frame()?;
                    self.read_state = ReadState::Init;
                    Ok(())
                } else {
                    self.read_state = ReadState::ReadControlContent;
                    self.step_read_control_content(cx, buf)
                }
            }
            OpCode::Unknown(_) => unreachable!("opcodes are validated in step_init"),
        }
    }

    fn finish_data_frame(&mut self) -> std::io::Result<()> {
        if self.read_frame_final && self.reading_text_message() && self.text_utf8_pending_len != 0 {
            self.error_close_code = 1007;
            return Err(invalid_utf8_error());
        }
        if self.read_frame_opcode == OpCode::Continue && self.read_frame_final {
            self.fragmented_message = None;
        }
        Ok(())
    }

    fn reading_text_message(&self) -> bool {
        self.read_frame_opcode == OpCode::Text
            || (self.read_frame_opcode == OpCode::Continue
                && self.fragmented_message == Some(OpCode::Text))
    }

    fn finish_control_frame(&mut self) -> std::io::Result<()> {
        match self.read_frame_opcode {
            OpCode::Ping => {
                self.pending_control = Some(OpCode::Pong);
                self.control_flush_pending = true;
            }
            OpCode::Pong => {
                // A Pong may carry any payload up to the control-frame limit. It does not
                // need to correspond to a Ping that this endpoint remembers sending.
            }
            OpCode::Close => {
                if self.control_data_size >= 2
                    && std::str::from_utf8(&self.control_data[2..self.control_data_size]).is_err()
                {
                    self.error_close_code = 1007;
                }
                validate_close_payload(&self.control_data[..self.control_data_size])?;
                self.close_received = true;
                if !self.close_sent {
                    self.pending_control = Some(OpCode::Close);
                    self.control_flush_pending = true;
                }
            }
            _ => unreachable!("only control frames have control content"),
        }
        Ok(())
    }

    fn step_read_control_content(
        &mut self,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        let remaining_length = usize::try_from(self.read_frame_length).unwrap_or(usize::MAX);
        let read_amount = std::cmp::min(unprocessed_len, remaining_length);
        if read_amount == 0 {
            return Ok(());
        }

        let content_bytes = &mut self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + read_amount];
        if self.read_frame_masked {
            let iter = content_bytes.iter_mut().zip(
                self.read_frame_mask
                    .iter()
                    .cycle()
                    .skip(self.read_frame_mask_offset),
            );
            for (byte, &key) in iter {
                *byte ^= key
            }
            self.read_frame_mask_offset = (self.read_frame_mask_offset + read_amount) % 4;
        }

        self.control_data[self.control_data_size..self.control_data_size + read_amount]
            .copy_from_slice(content_bytes);
        self.control_data_size += read_amount;
        self.unprocessed_start_offset += read_amount;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }
        self.read_frame_length -= read_amount as u64;

        if self.read_frame_length == 0 {
            self.read_frame_mask_offset = 0;
            self.read_state = ReadState::Init;
            self.finish_control_frame()?;
        }

        Ok(())
    }

    fn step_read_data_content(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;

        let available_space = buf.remaining();
        if available_space == 0 {
            // it's possible that we looped through all the steps and ended up in read content
            // with no space.
            return Ok(());
        }

        let remaining_length = usize::try_from(self.read_frame_length).unwrap_or(usize::MAX);
        let read_amount = std::cmp::min(
            std::cmp::min(unprocessed_len, remaining_length),
            available_space,
        );

        if read_amount == 0 {
            return Ok(());
        }

        let reading_text_message = self.reading_text_message();
        let content_bytes = &mut self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + read_amount];
        if self.read_frame_masked {
            let iter = content_bytes.iter_mut().zip(
                self.read_frame_mask
                    .iter()
                    .cycle()
                    .skip(self.read_frame_mask_offset),
            );
            for (byte, &key) in iter {
                *byte ^= key
            }
            self.read_frame_mask_offset = (self.read_frame_mask_offset + read_amount) % 4;
        }

        let completes_message =
            self.read_frame_final && self.read_frame_length == read_amount as u64;
        if reading_text_message
            && validate_utf8_chunk(
                &mut self.text_utf8_pending,
                &mut self.text_utf8_pending_len,
                content_bytes,
                completes_message,
            )
            .is_err()
        {
            self.error_close_code = 1007;
            return Err(invalid_utf8_error());
        }

        // Data received after sending Close is consumed only to reach the
        // peer's Close response and is never delivered to the application.
        if !self.close_sent {
            buf.put_slice(content_bytes);
        }

        self.unprocessed_start_offset += read_amount;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.read_frame_length -= read_amount as u64;
        if self.read_frame_length == 0 {
            self.read_frame_mask_offset = 0;
            self.finish_data_frame()?;
            self.read_state = ReadState::Init;
        }

        Ok(())
    }

    fn pack_write_ping_frame(&mut self) -> bool {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;
        if available_space < 6 {
            return false;
        }

        let written = pack_frame(
            0x09,
            self.is_client,
            &[],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        true
    }

    fn pack_write_empty_frame(&mut self) -> bool {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;
        if available_space < 6 {
            return false;
        }

        // 0x02 is binary
        let written = pack_frame(
            0x02,
            self.is_client,
            &[],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        true
    }

    fn pack_pending_control_frame(&mut self) -> bool {
        let Some(opcode) = self.pending_control else {
            return true;
        };
        let available_space = self.write_frame.len() - self.write_frame_end_offset;

        // up to 14 bytes for header and mask
        if available_space < self.control_data_size + 14 {
            return false;
        }

        let opcode_byte = match opcode {
            OpCode::Close => 0x08,
            OpCode::Pong => 0x0a,
            _ => unreachable!("only close and pong frames may be pending"),
        };
        let written = pack_frame(
            opcode_byte,
            self.is_client,
            &self.control_data[0..self.control_data_size],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;
        self.pending_control = None;
        if opcode == OpCode::Close {
            self.close_sent = true;
        }

        true
    }

    fn pack_write_frame(&mut self, input: &[u8]) -> usize {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;

        // we need up to 14 bytes just for the header and mask.
        if available_space < 40 {
            return 0;
        }

        let pack_amount = std::cmp::min(input.len(), available_space - 14);

        // 0x02 is binary
        let written = pack_frame(
            0x02,
            self.is_client,
            &input[0..pack_amount],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        pack_amount
    }

    fn do_write_frame(&mut self, cx: &mut Context<'_>) -> std::io::Result<()> {
        loop {
            let remaining_data =
                &self.write_frame[self.write_frame_start_offset..self.write_frame_end_offset];

            match Pin::new(&mut self.stream).poll_write(cx, remaining_data) {
                Poll::Ready(Ok(written)) => {
                    if written == 0 {
                        // eof, TODO fix
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "write frame eof",
                        ));
                    }
                    self.write_frame_start_offset += written;
                    if self.write_frame_start_offset == self.write_frame_end_offset {
                        self.write_frame_start_offset = 0;
                        self.write_frame_end_offset = 0;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
                Poll::Pending => {
                    break;
                }
            }
        }

        Ok(())
    }

    fn poll_flush_pending_control(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            if self.pending_control.is_some() && !self.pack_pending_control_frame() {
                self.do_write_frame(cx)?;
                if self.write_frame_end_offset > 0 {
                    return Poll::Pending;
                }
                continue;
            }

            if self.write_frame_end_offset > 0 {
                self.do_write_frame(cx)?;
                if self.write_frame_end_offset > 0 {
                    return Poll::Pending;
                }
            }

            return match Pin::new(&mut self.stream).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.control_flush_pending = false;
                    Poll::Ready(Ok(()))
                }
                other => other,
            };
        }
    }

    fn reset_unprocessed_buf_offset(&mut self) {
        assert!(
            self.unprocessed_start_offset > 0
                && self.unprocessed_end_offset > self.unprocessed_start_offset
        );

        self.unprocessed_buf.copy_within(
            self.unprocessed_start_offset..self.unprocessed_end_offset,
            0,
        );
        self.unprocessed_end_offset -= self.unprocessed_start_offset;
        self.unprocessed_start_offset = 0;
    }
}

impl AsyncRead for WebsocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if this.read_closed {
            return Poll::Ready(Ok(()));
        }

        if this.control_flush_pending {
            ready!(this.poll_flush_pending_control(cx))?;
        }

        if let Some(message) = this.terminal_error.take() {
            this.read_closed = true;
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            )));
        }

        if this.close_received {
            this.read_closed = true;
            return Poll::Ready(Ok(()));
        }

        loop {
            // Reset the offset if we have less than half the buffer left to use.
            if this.unprocessed_start_offset > 0
                && this.unprocessed_end_offset > this.unprocessed_start_offset
                && this.unprocessed_start_offset * 2 > this.unprocessed_buf.len()
            {
                this.reset_unprocessed_buf_offset();
            }

            if this.pending_initial_data {
                this.pending_initial_data = false;
            }

            let has_buffered_data = this.unprocessed_end_offset > this.unprocessed_start_offset;
            if has_buffered_data {
                let before_state = this.read_state;
                let before_start = this.unprocessed_start_offset;
                let before_end = this.unprocessed_end_offset;
                let before_remaining = this.read_frame_length;

                let read_result = match this.read_state {
                    ReadState::Init => this.step_init(cx, buf),
                    ReadState::ReadLength { length_bytes_len } => {
                        this.step_read_length(cx, buf, length_bytes_len)
                    }
                    ReadState::ReadMask => this.step_read_mask(cx, buf),
                    ReadState::ReadDataContent => this.step_read_data_content(cx, buf),
                    ReadState::ReadControlContent => this.step_read_control_content(cx, buf),
                };

                if let Err(error) = read_result {
                    this.control_data[..2].copy_from_slice(&this.error_close_code.to_be_bytes());
                    this.control_data_size = 2;
                    this.pending_control = Some(OpCode::Close);
                    this.control_flush_pending = true;
                    this.terminal_error = Some(error.to_string());
                    ready!(this.poll_flush_pending_control(cx))?;
                    let message = this
                        .terminal_error
                        .take()
                        .expect("terminal protocol error was just stored");
                    this.read_closed = true;
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        message,
                    )));
                }

                if this.control_flush_pending {
                    ready!(this.poll_flush_pending_control(cx))?;
                    if let Some(message) = this.terminal_error.take() {
                        this.read_closed = true;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            message,
                        )));
                    }
                    if this.close_received {
                        this.read_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                }
                if this.close_received {
                    this.read_closed = true;
                    return Poll::Ready(Ok(()));
                }

                if buf.filled().len() > filled_before {
                    return Poll::Ready(Ok(()));
                }

                let progressed = this.read_state != before_state
                    || this.unprocessed_start_offset != before_start
                    || this.unprocessed_end_offset != before_end
                    || this.read_frame_length != before_remaining;
                if progressed {
                    continue;
                }
            }

            // The current parser state needs more bytes. Compact any partially
            // consumed input before polling the transport, then process the new
            // bytes on the next loop iteration. This ordering is important when
            // multiple frames arrive in a single TCP read.
            if this.unprocessed_start_offset > 0
                && this.unprocessed_end_offset > this.unprocessed_start_offset
            {
                this.reset_unprocessed_buf_offset();
            }
            if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                this.control_data[..2].copy_from_slice(&1002u16.to_be_bytes());
                this.control_data_size = 2;
                this.pending_control = Some(OpCode::Close);
                this.control_flush_pending = true;
                this.terminal_error =
                    Some("websocket frame header exceeds the bounded read buffer".to_string());
                continue;
            }
            let mut read_buf =
                ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(res) => {
                    res?;
                    let len = read_buf.filled().len();
                    if len == 0 {
                        this.read_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.unprocessed_end_offset += len;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WebsocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.close_received || this.close_sent {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "websocket closing handshake has started",
            )));
        }

        if this.control_flush_pending {
            ready!(this.poll_flush_pending_control(cx))?;
        }

        let mut written = 0;
        loop {
            let input = &buf[written..];
            if input.is_empty() {
                break;
            }

            written += this.pack_write_frame(input);

            if let Err(e) = this.do_write_frame(cx) {
                return Poll::Ready(Err(e));
            }

            if this.write_frame_end_offset > 0 {
                // Not everything could be written.
                break;
            }
        }

        if written > 0 {
            Poll::Ready(Ok(written))
        } else {
            Poll::Pending
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.control_flush_pending {
            ready!(this.poll_flush_pending_control(cx))?;
        }

        if this.write_frame_end_offset == 0 {
            return Pin::new(&mut this.stream).poll_flush(cx);
        }

        // Create a new write frame when flush is called when we don't have one.
        while this.write_frame_end_offset > 0 {
            match this.do_write_frame(cx) {
                Ok(()) => {
                    if this.write_frame_end_offset > 0 {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        }

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.close_sent && !this.close_received && this.pending_control.is_none() {
            this.control_data_size = 0;
            this.pending_control = Some(OpCode::Close);
            this.control_flush_pending = true;
        }
        if this.control_flush_pending {
            ready!(this.poll_flush_pending_control(cx))?;
        }
        if !this.close_received && !this.read_closed {
            let mut discard = [0u8; 1024];
            let mut read_buf = ReadBuf::new(&mut discard);
            ready!(Pin::new(&mut *this).poll_read(cx, &mut read_buf))?;
            if !this.close_received && !this.read_closed {
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for WebsocketStream {
    fn supports_ping(&self) -> bool {
        self.ping_type != WebsocketPingType::Disabled
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        let this = self.get_mut();

        if this.close_received || this.close_sent {
            return Poll::Ready(Ok(false));
        }

        if this.control_flush_pending {
            ready!(this.poll_flush_pending_control(cx))?;
            return Poll::Ready(Ok(true));
        }

        // Don't bother writing a ping if we have other things to write.
        if this.write_frame_end_offset > 0 {
            return Poll::Ready(Ok(false));
        }

        let written = match this.ping_type {
            WebsocketPingType::PingFrame => this.pack_write_ping_frame(),
            WebsocketPingType::EmptyFrame => this.pack_write_empty_frame(),
            _ => {
                return Poll::Ready(Err(std::io::Error::other(
                    "websocket ping disabled; poll_flush_write should not be reached",
                )));
            }
        };

        // the write frame should be empty so there should always be space.
        assert!(written);

        Poll::Ready(Ok(true))
    }
}

impl AsyncStream for WebsocketStream {}

#[inline]
fn pack_frame(opcode: u8, use_mask: bool, input: &[u8], output: &mut [u8]) -> usize {
    let input_len = input.len();

    // 0x80 is final
    output[0] = opcode | 0x80;

    let mut offset = if input_len < 126 {
        output[1] = input_len as u8;
        2
    } else if input_len <= 65535 {
        output[1] = 0x7e;
        let size_bytes = (input_len as u16).to_be_bytes();
        output[2..4].copy_from_slice(&size_bytes);
        4
    } else {
        output[1] = 0x7f;
        let size_bytes = (input_len as u64).to_be_bytes();
        output[2..10].copy_from_slice(&size_bytes);
        10
    };

    // Client must be masked, but optional for server.
    let mask = if use_mask {
        // set the masking bit
        output[1] |= 0x80;

        let mut mask_bytes = [0u8; 4];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut mask_bytes);

        output[offset..offset + 4].copy_from_slice(&mask_bytes);
        offset += 4;

        Some(mask_bytes)
    } else {
        None
    };

    if input_len > 0 {
        output[offset..offset + input_len].copy_from_slice(input);
        if let Some(mask_bytes) = mask {
            let iter = output[offset..offset + input_len]
                .iter_mut()
                .zip(mask_bytes.iter().cycle());
            for (byte, &key) in iter {
                *byte ^= key
            }
        }
    }

    offset + input_len
}

fn validate_close_payload(payload: &[u8]) -> std::io::Result<()> {
    if payload.len() == 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "close frame payload must be empty or contain a two-byte status code",
        ));
    }
    if payload.is_empty() {
        return Ok(());
    }

    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let valid_code = matches!(
        code,
        1000 | 1001 | 1002 | 1003 | 1007 | 1008 | 1009 | 1010 | 1011 | 1012 | 1013 | 1014
    ) || (3000..=4999).contains(&code);
    if !valid_code {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid websocket close status code ({code})"),
        ));
    }

    std::str::from_utf8(&payload[2..]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "websocket close reason is not valid UTF-8",
        )
    })?;
    Ok(())
}

fn invalid_utf8_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "websocket text message is not valid UTF-8",
    )
}

fn utf8_sequence_width(first: u8) -> Option<usize> {
    match first {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

/// Validate a text message incrementally without buffering the complete
/// message. At most the three-byte incomplete suffix of a UTF-8 sequence is
/// retained across reads and continuation frames.
fn validate_utf8_chunk(
    pending: &mut [u8; 3],
    pending_len: &mut usize,
    chunk: &[u8],
    final_message_chunk: bool,
) -> std::io::Result<()> {
    let mut chunk_offset = 0;
    if *pending_len > 0 {
        let width = utf8_sequence_width(pending[0]).ok_or_else(invalid_utf8_error)?;
        let needed = width - *pending_len;
        let take = needed.min(chunk.len());
        let mut sequence = [0u8; 4];
        sequence[..*pending_len].copy_from_slice(&pending[..*pending_len]);
        sequence[*pending_len..*pending_len + take].copy_from_slice(&chunk[..take]);
        if take < needed {
            pending[*pending_len..*pending_len + take].copy_from_slice(&chunk[..take]);
            *pending_len += take;
            if final_message_chunk {
                return Err(invalid_utf8_error());
            }
            return Ok(());
        }
        std::str::from_utf8(&sequence[..width]).map_err(|_| invalid_utf8_error())?;
        *pending_len = 0;
        chunk_offset = take;
    }

    match std::str::from_utf8(&chunk[chunk_offset..]) {
        Ok(_) => Ok(()),
        Err(error) if error.error_len().is_some() => Err(invalid_utf8_error()),
        Err(error) => {
            let incomplete = &chunk[chunk_offset + error.valid_up_to()..];
            if final_message_chunk || incomplete.len() > pending.len() {
                return Err(invalid_utf8_error());
            }
            pending[..incomplete.len()].copy_from_slice(incomplete);
            *pending_len = incomplete.len();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
    };
    use tokio::time::{Duration, timeout};

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            unreachable!("test stream does not support ping")
        }
    }

    impl AsyncStream for TestStream {}

    fn server_stream(io: DuplexStream) -> WebsocketStream {
        WebsocketStream::new(
            Box::new(TestStream(io)),
            false,
            WebsocketPingType::Disabled,
            &[],
        )
    }

    fn masked_frame(first_byte: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0x11, 0x22, 0x33, 0x44];
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(first_byte);
        match payload.len() {
            0..=125 => frame.push(0x80 | payload.len() as u8),
            126..=65535 => {
                frame.push(0xfe);
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            _ => {
                frame.push(0xff);
                frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .zip(mask.iter().cycle())
                .map(|(byte, key)| byte ^ key),
        );
        frame
    }

    async fn assert_server_rejects(frame: &[u8], expected_message: &str) {
        assert_server_rejects_with_code(frame, expected_message, 1002).await;
    }

    async fn assert_server_rejects_with_code(
        frame: &[u8],
        expected_message: &str,
        close_code: u16,
    ) {
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = server_stream(server_io);
        peer_io.write_all(frame).await.unwrap();

        let err = stream.read_u8().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains(expected_message),
            "unexpected error: {err}"
        );

        let mut close = [0u8; 4];
        peer_io.read_exact(&mut close).await.unwrap();
        assert_eq!(&close[..2], &[0x88, 0x02]);
        assert_eq!(u16::from_be_bytes([close[2], close[3]]), close_code);
    }

    #[tokio::test]
    async fn server_rejects_unmasked_client_frame() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = server_stream(server_io);

        peer_io.write_all(&[0x82, 0x01, b'x']).await.unwrap();

        let err = stream.read_u8().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("not masked"));
    }

    #[tokio::test]
    async fn server_rejects_frame_with_reserved_bits() {
        assert_server_rejects(&[0xc2, 0x80, 1, 2, 3, 4], "reserved").await;
    }

    #[tokio::test]
    async fn server_rejects_reserved_opcode_and_invalid_control_headers() {
        assert_server_rejects(&masked_frame(0x83, b""), "opcode").await;
        assert_server_rejects(&masked_frame(0x09, b""), "must not be fragmented").await;
        assert_server_rejects(&[0x89, 0xfe, 0, 126, 1, 2, 3, 4], "exceeds 125").await;
    }

    #[tokio::test]
    async fn server_rejects_noncanonical_and_invalid_extended_lengths() {
        assert_server_rejects(&[0x82, 0xfe, 0, 125, 1, 2, 3, 4], "non-canonical 16-bit").await;
        assert_server_rejects(
            &[0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4],
            "non-canonical 64-bit",
        )
        .await;
        assert_server_rejects(
            &[0x82, 0xff, 0x80, 0, 0, 0, 0, 1, 0, 0, 1, 2, 3, 4],
            "invalid frame length",
        )
        .await;
    }

    #[tokio::test]
    async fn canonical_extended_length_is_accepted() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = server_stream(server_io);
        let payload = vec![0x5a; 126];
        peer_io
            .write_all(&masked_frame(0x82, &payload))
            .await
            .unwrap();

        let mut received = vec![0; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn fragmented_binary_message_accepts_interleaved_pong_payload() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = server_stream(server_io);
        let mut frames = masked_frame(0x02, b"hel");
        frames.extend_from_slice(&masked_frame(0x8a, b"not-empty"));
        frames.extend_from_slice(&masked_frame(0x80, b"lo"));
        peer_io.write_all(&frames).await.unwrap();

        let mut received = [0u8; 5];
        let first_read = stream.read(&mut received).await.unwrap();
        let second_read = stream.read(&mut received[first_read..]).await.unwrap();
        assert_eq!(first_read, 3);
        assert_eq!(second_read, 2);
        assert_eq!(first_read + second_read, received.len());
        assert_eq!(&received, b"hello");
    }

    #[tokio::test]
    async fn fragmented_text_message_validates_utf8_across_frames() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = server_stream(server_io);
        let mut frames = masked_frame(0x01, &[0xe4]);
        frames.extend_from_slice(&masked_frame(0x00, &[0xbd]));
        frames.extend_from_slice(&masked_frame(0x80, &[0xa0]));
        peer_io.write_all(&frames).await.unwrap();

        let mut received = [0u8; 3];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, "你".as_bytes());
    }

    #[tokio::test]
    async fn invalid_text_utf8_is_rejected_with_invalid_payload_close() {
        assert_server_rejects_with_code(&masked_frame(0x81, &[0xff]), "not valid UTF-8", 1007)
            .await;
    }

    #[tokio::test]
    async fn invalid_fragment_sequences_are_rejected() {
        assert_server_rejects(&masked_frame(0x80, b"orphan"), "without an open").await;

        let mut frames = masked_frame(0x02, b"first");
        frames.extend_from_slice(&masked_frame(0x82, b"second"));
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = server_stream(server_io);
        peer_io.write_all(&frames).await.unwrap();
        let mut first = [0u8; 5];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"first");
        let err = stream.read_u8().await.unwrap_err();
        assert!(err.to_string().contains("fragmented message"));
    }

    #[tokio::test]
    async fn ping_is_echoed_immediately_without_application_write() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = server_stream(server_io);
        let read_task = tokio::spawn(async move {
            let mut data = [0u8; 1];
            stream.read(&mut data).await
        });

        peer_io
            .write_all(&masked_frame(0x89, b"heartbeat"))
            .await
            .unwrap();

        let mut pong = [0u8; 11];
        timeout(Duration::from_secs(1), peer_io.read_exact(&mut pong))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&pong, b"\x8a\theartbeat");
        read_task.abort();
    }

    #[tokio::test]
    async fn close_is_echoed_and_ends_the_application_stream() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = server_stream(server_io);
        let close_payload = [0x03, 0xe8, b'b', b'y', b'e'];
        let mut frames = masked_frame(0x88, &close_payload);
        frames.extend_from_slice(&masked_frame(0x82, b"must not be delivered"));
        peer_io.write_all(&frames).await.unwrap();

        let mut data = [0u8; 1];
        assert_eq!(stream.read(&mut data).await.unwrap(), 0);
        assert_eq!(stream.read(&mut data).await.unwrap(), 0);

        let mut close = [0u8; 7];
        peer_io.read_exact(&mut close).await.unwrap();
        assert_eq!(&close[..2], &[0x88, 5]);
        assert_eq!(&close[2..], &close_payload);

        let err = stream.write_all(b"after close").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn malformed_close_payload_is_a_protocol_error() {
        assert_server_rejects(&masked_frame(0x88, &[0x03]), "two-byte status").await;
        assert_server_rejects(&masked_frame(0x88, &[0x03, 0xed]), "status code").await;
        assert_server_rejects_with_code(
            &masked_frame(0x88, &[0x03, 0xe8, 0xff]),
            "not valid UTF-8",
            1007,
        )
        .await;
    }

    #[tokio::test]
    async fn active_shutdown_waits_for_peer_close() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = server_stream(server_io);
        let shutdown = tokio::spawn(async move { stream.shutdown().await });

        let mut close = [0u8; 2];
        timeout(Duration::from_secs(1), peer_io.read_exact(&mut close))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(close, [0x88, 0x00]);
        peer_io
            .write_all(&masked_frame(0x88, &[0x03, 0xe8]))
            .await
            .unwrap();

        timeout(Duration::from_secs(1), shutdown)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn empty_write_is_noop() {
        let (client_io, mut peer_io) = duplex(1024);
        let mut stream = WebsocketStream::new(
            Box::new(TestStream(client_io)),
            true,
            WebsocketPingType::Disabled,
            &[],
        );

        let written = stream.write(&[]).await.unwrap();
        assert_eq!(written, 0);
        stream.flush().await.unwrap();

        let mut byte = [0u8; 1];
        assert!(
            timeout(Duration::from_millis(50), peer_io.read_exact(&mut byte))
                .await
                .is_err(),
            "empty write must not emit a WebSocket frame"
        );
    }

    #[tokio::test]
    async fn zero_sized_read_is_noop() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut stream = WebsocketStream::new(
            Box::new(TestStream(server_io)),
            true,
            WebsocketPingType::Disabled,
            &[],
        );

        let mut frame = [0u8; 16];
        let frame_len = pack_frame(0x02, false, b"ok", &mut frame);
        peer_io.write_all(&frame[..frame_len]).await.unwrap();

        let mut empty = [];
        let mut read_buf = ReadBuf::new(&mut empty);
        poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut read_buf))
            .await
            .unwrap();
        assert!(read_buf.filled().is_empty());

        let mut out = [0u8; 2];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ok");
    }
}
