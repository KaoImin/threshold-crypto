use std::fmt;

///
#[derive(Debug)]
pub enum Error {
    ///
    SignatureErr,
    ///
    NoPolyCoef,
    ///
    NumOfTermsErr,
    ///
    CoefsInexistence,
    ///
    SecretInexistence,
    ///
    NoCoef(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg: String = match *self {
            Error::NoCoef(i) => format!("Do not find coef in id {:?}", i),
            _ => format!(""),
        };
        f.write_fmt(format_args!("Threshold Crypto Error ({})", msg))
    }
}
