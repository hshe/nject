use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use std::ops::Deref;
use std::{io::Write, path::PathBuf};
use syn::{
    parse::{Parse, ParseStream},
    spanned::Spanned,
    AngleBracketedGenericArguments, Expr, ExprClosure, Fields, GenericArgument, GenericParam,
    Ident, Pat, PatType, Path, PathSegment, Type,
};

pub struct DeriveInput(syn::DeriveInput);

impl Deref for DeriveInput {
    type Target = syn::DeriveInput;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Parse for DeriveInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let input = input.parse()?;
        Ok(Self(input))
    }
}

impl ToTokens for DeriveInput {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.0.to_tokens(tokens)
    }
}

impl DeriveInput {
    pub fn fields(&self) -> &Fields {
        match &self.data {
            syn::Data::Struct(d) => &d.fields,
            _ => panic!("Unsupported type. Macro should be used on a struct"),
        }
    }
    pub fn field_types(&self) -> Vec<&Type> {
        self.fields().iter().map(|f| &f.ty).collect::<Vec<_>>()
    }
    pub fn field_idents(&self) -> Vec<&Ident> {
        self.fields()
            .iter()
            .map(|f| f.ident.as_ref())
            .filter_map(|i| i)
            .collect::<Vec<_>>()
    }
    pub fn generic_params(&self) -> Vec<&GenericParam> {
        self.generics.params.iter().collect::<Vec<_>>()
    }
    pub fn generic_keys(&self) -> Vec<TokenStream> {
        self.generics
            .params
            .iter()
            .map(|p| match p {
                GenericParam::Type(t) => {
                    let identity = &t.ident;
                    quote! { #identity }
                }
                GenericParam::Const(c) => {
                    let identity = &c.ident;
                    quote! { #identity }
                }
                GenericParam::Lifetime(l) => quote! { #l },
            })
            .collect::<Vec<_>>()
    }
    pub fn lifetime_keys(&self) -> Vec<TokenStream> {
        self.generics
            .params
            .iter()
            .filter_map(|p| match p {
                GenericParam::Lifetime(l) => Some(quote! { #l }),
                _ => None,
            })
            .collect::<Vec<_>>()
    }
}

pub struct FactoryExpr {
    pub inputs: Vec<PatType>,
    pub body: Box<Expr>,
}

impl Parse for FactoryExpr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let expr: ExprClosure = input.parse()?;
        let mut inputs = Vec::with_capacity(expr.inputs.len());
        let span = expr.span();
        for input in expr.inputs {
            if let Pat::Type(pat_type) = input {
                inputs.push(pat_type);
            } else {
                return Err(syn::Error::new(
                    span,
                    format!("Invalid input: {}", input.to_token_stream()),
                ));
            }
        }
        Ok(FactoryExpr {
            inputs,
            body: expr.body,
        })
    }
}

pub fn extract_path_from_type(ty: &Type) -> &Path {
    match ty {
        Type::Path(p) => &p.path,
        Type::Reference(r) => extract_path_from_type(&r.elem),
        _ => panic!("Unsupported type. Must be a Path or a Reference type."),
    }
}

pub fn cache_path() -> PathBuf {
    let root_path = env!("NJECT_OUT_DIR");
    std::path::Path::new(root_path).join(".nject")
}

pub fn retry<T, E>(times: usize, action: impl Fn() -> Result<T, E>) -> Result<T, E> {
    let result = action();
    if result.is_ok() {
        result
    } else if times <= 0 {
        result
    } else {
        std::thread::sleep(std::time::Duration::from_millis(100));
        retry(times - 1, action)
    }
}

pub fn encode(data: &str) -> String {
    let mut encoded_data = Vec::with_capacity(data.len() * 2);
    for d in data.as_bytes() {
        write!(&mut encoded_data, "{:X}", d).expect("Unable to encode data");
    }
    String::from_utf8(encoded_data).expect("Unable to encode data.")
}

pub fn decode(data: &str) -> String {
    let decoded_data = (0..data.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(data.get(i..i + 2).expect("Unable to decode data."), 16)
                .expect("Unable to decode data.")
        })
        .collect::<Vec<u8>>();
    String::from_utf8(decoded_data).expect("Unable to decode data.")
}

pub fn substitute_in_path(path: &mut Path, from: &str, to: &str) {
    for segment in path.segments.iter_mut() {
        substitute_in_path_segment(segment, from, to)
    }
}

fn substitute_in_path_segment(segment: &mut PathSegment, from: &str, to: &str) {
    if segment.ident.to_string().eq(from) {
        segment.ident = syn::Ident::new(to, segment.ident.span());
    }
    let arguments = &mut segment.arguments;
    match arguments {
        syn::PathArguments::None => (),
        syn::PathArguments::AngleBracketed(ref mut b) => {
            for arg in &mut b.args {
                substitute_in_generic_argument(arg, from, to)
            }
        }
        syn::PathArguments::Parenthesized(ref mut p) => {
            for ty in &mut p.inputs {
                substitute_in_type(ty, from, to)
            }
        }
    };
}

fn substitute_in_angle_bracketed_generic_arguments(
    args: &mut AngleBracketedGenericArguments,
    from: &str,
    to: &str,
) {
    for arg in &mut args.args {
        substitute_in_generic_argument(arg, from, to)
    }
}

fn substitute_in_generic_argument(arg: &mut GenericArgument, from: &str, to: &str) {
    match arg {
        syn::GenericArgument::Type(ref mut ty) => substitute_in_type(ty, from, to),
        syn::GenericArgument::Const(_) => (),
        syn::GenericArgument::AssocType(ref mut a) => {
            if let Some(ref mut args) = &mut a.generics {
                substitute_in_angle_bracketed_generic_arguments(args, from, to)
            }
            substitute_in_type(&mut a.ty, from, to)
        }
        syn::GenericArgument::AssocConst(_) => (),
        syn::GenericArgument::Constraint(ref mut c) => {
            if let Some(ref mut args) = &mut c.generics {
                substitute_in_angle_bracketed_generic_arguments(args, from, to)
            }
            for bound in &mut c.bounds {
                match bound {
                    syn::TypeParamBound::Trait(ref mut t) => {
                        substitute_in_path(&mut t.path, from, to)
                    }
                    syn::TypeParamBound::Lifetime(_) => (),
                    syn::TypeParamBound::Verbatim(_) => (),
                    _ => (),
                };
            }
        }
        _ => (),
    }
}

pub fn substitute_in_type(ty: &mut Type, from: &str, to: &str) {
    match ty {
        Type::Path(ref mut p) => substitute_in_path(&mut p.path, from, to),
        Type::Reference(ref mut r) => substitute_in_type(&mut r.elem, from, to),
        _ => panic!("Unsupported type. Must be a Path or a Reference type."),
    };
}
