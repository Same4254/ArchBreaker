use std::usize;

pub struct MyReader
{
    pub buff: Box<[u8]>,
    pub cursor: usize,
}

impl MyReader
{
    pub fn seek(&mut self, pos: usize) -> std::io::Result<&mut Self>
    {
        if pos >= self.buff.len()
        {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        } else {
            self.cursor = pos;
            return Ok(self);
        }
    }

    pub fn has_next_byte(&self) -> bool
    {
        return self.buff.len() > 0 && self.cursor < self.buff.len();
    }

    pub fn peek_byte(&mut self) -> std::io::Result<u8>
    {
        if self.cursor >= self.buff.len()
        {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        } else {
            return Ok(self.buff[self.cursor]);
        }
    }

    pub fn take_byte(&mut self) -> std::io::Result<u8>
    {
        match self.peek_byte()
        {
            Ok(v) => {
                self.cursor += 1;
                Ok (v)
            },

            Err(e) => Err(e)
        }
    }

    pub fn take_bytes(&mut self, num_bytes: usize) -> std::io::Result<&[u8]>
    {
        if self.cursor + num_bytes >= self.buff.len()
        {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        } else {
            let to_ret = Ok(&self.buff[self.cursor .. self.cursor+num_bytes]);
            self.cursor += num_bytes;

            return to_ret;
        }
    }
}

pub fn bytes_to_int (bytes: &[u8]) -> i64
{
    let mut ret: u64 = 0;
    for i in bytes.iter().rev()
    {
        ret <<= 8;
        ret |= *i as u64;
    }

    return ret as i64;
}