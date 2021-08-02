use std::convert::Infallible;

use bytes::Bytes;
use nom::combinator::{cond, map_res};
use nom::error::{ContextError, Error as NomError, ErrorKind as NomErrorKind};
use nom::{
    bits::bits, bits::complete::take as take_bits, combinator::map,
    error::ParseError as NomParseError, number::complete::be_u32, sequence::tuple,
};
use pretty_hex::*;

#[derive(Debug)]
pub enum ErrorKind {
    Nom(NomErrorKind),
    Context(&'static str),
}

#[derive(Debug)]
pub struct Error<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<I> NomParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: NomErrorKind) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }

    fn append(input: I, kind: NomErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }
}

impl<I> ContextError<I> for Error<I> {
    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}

pub type Input<'a> = &'a [u8];
pub type Result<'a, T> = nom::IResult<Input<'a>, T, Error<Input<'a>>>;

#[derive(Debug)]
pub struct Frame {
    pub fin: u8,
    pub rsv: u8,
    pub mask: u8,
    pub opcode: u8,
    pub length: u8,
    pub masking_key: u32,
}

impl<I> nom::ErrorConvert<Error<I>> for NomError<I> {
    fn convert(self) -> Error<I> {
        let errors = vec![(self.input, ErrorKind::Nom(self.code))];
        Error { errors }
    }
}

impl<I> nom::ErrorConvert<Error<I>> for NomError<(I, usize)> {
    fn convert(self) -> Error<I> {
        let errors = vec![(self.input.0, ErrorKind::Nom(self.code))];
        Error { errors }
    }
}

impl<I> From<nom::Err<Error<I>>> for crate::Error {
    fn from(_: nom::Err<Error<I>>) -> Self {
        crate::Error::Derp
    }
}

impl Frame {
    pub fn parse_masking_key(input: &[u8]) -> Result<u32> {
        be_u32(input)
    }

    pub fn parse_pre_payload(input: &[u8]) -> Result<(u8, u8, u8, u8, u8)> {
        bits::<_, _, NomError<(&[u8], usize)>, _, _>(tuple((
            take_bits(1usize),
            take_bits(3usize),
            take_bits(4usize),
            take_bits(1usize),
            take_bits(7usize),
        )))(input)
    }

    pub fn from_bytes(input: Vec<u8>) -> std::result::Result<(Vec<u8>, Frame), crate::Error> {
        println!("input: {}", input.hex_dump());
        let (rest, parsed) = Self::parse_pre_payload(&input)?;
        let (fin, rsv, opcode, mask, payload_hint) = parsed;
        let payload_word_len = match payload_hint {
            126 => 16,
            127 => 64,
            _ => payload_hint,
        };
        let payload = cond(payload_word_len >= 16, take_bits(payload_word_len));

        let (rest, frame) = map(
            tuple((
                bits::<_, _, NomError<(&[u8], usize)>, _, _>(payload),
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
        )(rest)?;

        Ok((rest.to_owned(), frame))
    }
}
