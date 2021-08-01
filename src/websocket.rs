use pretty_hex::*;
use std::convert::Infallible;

use nom::combinator::cond;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u32;
use nom::{
    bits::bits, bits::bytes, bits::complete::take, bytes::complete::take as take_bytes,
    combinator::map, error::ParseError, sequence::tuple, IResult,
};

pub type Result<'a, T> = IResult<(&'a [u8], usize), T, Error<&'a [u8]>>;

#[derive(Debug)]
pub struct Frame {
    pub fin: u8,
    pub rsv: u8,
    pub mask: u8,
    pub opcode: u8,
    pub length: u8,
    pub masking_key: u32,
}

impl Frame {
    pub fn parse_masking_key(input: &[u8]) -> IResult<&[u8], u32> {
        be_u32(input)
    }

    pub fn parse_pre_payload(input: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8, u8)> {
        let fin = take::<_, u8, _, _>(1usize);
        let rsv = take::<_, u8, _, _>(3usize);
        let opcode = take::<_, u8, _, _>(4usize);
        let mask = take::<_, u8, _, _>(1usize);
        let payload_hint = take::<_, u8, _, _>(7usize);
        bits::<_, _, Error<(&[u8], usize)>, _, _>(tuple((fin, rsv, opcode, mask, payload_hint)))(
            input,
        )
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Frame> {
        println!("input: {}", input.hex_dump());
        let (rest, parsed) = Self::parse_pre_payload(input)?;
        let (fin, rsv, opcode, mask, payload_hint) = parsed;
        let payload_word_len = match payload_hint {
            126 => 16,
            127 => 64,
            _ => payload_hint,
        };
        let payload = cond(payload_word_len >= 16, take(payload_word_len));
        map(
            tuple((
                bits::<_, _, Error<(&[u8], usize)>, _, _>(payload),
                Self::parse_masking_key,
            )),
            move |(payload, masking_key)| Self {
                fin,
                rsv,
                mask,
                opcode,
                length: payload.unwrap_or(payload_word_len),
                masking_key,
            },
        )(rest)
    }
}
