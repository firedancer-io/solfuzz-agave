use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use proc_macro2::{Literal, TokenStream};
use quote::{quote, ToTokens, TokenStreamExt};
use syn::Expr;

pub(crate) enum BigIntWrapper<'a> {
    Integer(BigInt),
    Constant(&'a Expr, usize),
}

impl<'a> From<BigInt> for BigIntWrapper<'a> {
    #[inline]
    fn from(v: BigInt) -> BigIntWrapper<'a> {
        BigIntWrapper::Integer(v)
    }
}

impl<'a> From<(&'a Expr, usize)> for BigIntWrapper<'a> {
    #[inline]
    fn from((expr, counter): (&'a Expr, usize)) -> BigIntWrapper<'a> {
        BigIntWrapper::Constant(expr, counter)
    }
}

impl<'a> ToTokens for BigIntWrapper<'a> {
    #[inline]
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            BigIntWrapper::Integer(v) => {
                let lit = if v.is_negative() {
                    Literal::i128_unsuffixed(v.to_i128().unwrap())
                } else {
                    Literal::u128_unsuffixed(v.to_u128().unwrap())
                };

                tokens.append(lit);
            },
            BigIntWrapper::Constant(expr, counter) => {
                let counter = *counter;

                if counter > 0 {
                    tokens.extend(quote!(#expr +));
                    tokens.append(Literal::usize_unsuffixed(counter));
                } else {
                    tokens.extend(quote!(#expr));
                }
            },
        }
    }
}
