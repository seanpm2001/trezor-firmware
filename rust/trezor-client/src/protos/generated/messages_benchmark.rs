// This file is generated by rust-protobuf 3.3.0. Do not edit
// .proto file is parsed by protoc 3.19.6
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `messages-benchmark.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_3_0;

// @@protoc_insertion_point(message:hw.trezor.messages.bitcoin.BenchmarkListNames)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct BenchmarkListNames {
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.bitcoin.BenchmarkListNames.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a BenchmarkListNames {
    fn default() -> &'a BenchmarkListNames {
        <BenchmarkListNames as ::protobuf::Message>::default_instance()
    }
}

impl BenchmarkListNames {
    pub fn new() -> BenchmarkListNames {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(0);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<BenchmarkListNames>(
            "BenchmarkListNames",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for BenchmarkListNames {
    const NAME: &'static str = "BenchmarkListNames";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> BenchmarkListNames {
        BenchmarkListNames::new()
    }

    fn clear(&mut self) {
        self.special_fields.clear();
    }

    fn default_instance() -> &'static BenchmarkListNames {
        static instance: BenchmarkListNames = BenchmarkListNames {
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for BenchmarkListNames {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("BenchmarkListNames").unwrap()).clone()
    }
}

impl ::std::fmt::Display for BenchmarkListNames {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BenchmarkListNames {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:hw.trezor.messages.bitcoin.BenchmarkNames)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct BenchmarkNames {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.bitcoin.BenchmarkNames.names)
    pub names: ::std::vec::Vec<::std::string::String>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.bitcoin.BenchmarkNames.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a BenchmarkNames {
    fn default() -> &'a BenchmarkNames {
        <BenchmarkNames as ::protobuf::Message>::default_instance()
    }
}

impl BenchmarkNames {
    pub fn new() -> BenchmarkNames {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(1);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "names",
            |m: &BenchmarkNames| { &m.names },
            |m: &mut BenchmarkNames| { &mut m.names },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<BenchmarkNames>(
            "BenchmarkNames",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for BenchmarkNames {
    const NAME: &'static str = "BenchmarkNames";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.names.push(is.read_string()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        for value in &self.names {
            my_size += ::protobuf::rt::string_size(1, &value);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        for v in &self.names {
            os.write_string(1, &v)?;
        };
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> BenchmarkNames {
        BenchmarkNames::new()
    }

    fn clear(&mut self) {
        self.names.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static BenchmarkNames {
        static instance: BenchmarkNames = BenchmarkNames {
            names: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for BenchmarkNames {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("BenchmarkNames").unwrap()).clone()
    }
}

impl ::std::fmt::Display for BenchmarkNames {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BenchmarkNames {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:hw.trezor.messages.bitcoin.BenchmarkRun)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct BenchmarkRun {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.bitcoin.BenchmarkRun.name)
    pub name: ::std::option::Option<::std::string::String>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.bitcoin.BenchmarkRun.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a BenchmarkRun {
    fn default() -> &'a BenchmarkRun {
        <BenchmarkRun as ::protobuf::Message>::default_instance()
    }
}

impl BenchmarkRun {
    pub fn new() -> BenchmarkRun {
        ::std::default::Default::default()
    }

    // optional string name = 1;

    pub fn name(&self) -> &str {
        match self.name.as_ref() {
            Some(v) => v,
            None => "",
        }
    }

    pub fn clear_name(&mut self) {
        self.name = ::std::option::Option::None;
    }

    pub fn has_name(&self) -> bool {
        self.name.is_some()
    }

    // Param is passed by value, moved
    pub fn set_name(&mut self, v: ::std::string::String) {
        self.name = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_name(&mut self) -> &mut ::std::string::String {
        if self.name.is_none() {
            self.name = ::std::option::Option::Some(::std::string::String::new());
        }
        self.name.as_mut().unwrap()
    }

    // Take field
    pub fn take_name(&mut self) -> ::std::string::String {
        self.name.take().unwrap_or_else(|| ::std::string::String::new())
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(1);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "name",
            |m: &BenchmarkRun| { &m.name },
            |m: &mut BenchmarkRun| { &mut m.name },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<BenchmarkRun>(
            "BenchmarkRun",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for BenchmarkRun {
    const NAME: &'static str = "BenchmarkRun";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.name = ::std::option::Option::Some(is.read_string()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.name.as_ref() {
            my_size += ::protobuf::rt::string_size(1, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.name.as_ref() {
            os.write_string(1, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> BenchmarkRun {
        BenchmarkRun::new()
    }

    fn clear(&mut self) {
        self.name = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static BenchmarkRun {
        static instance: BenchmarkRun = BenchmarkRun {
            name: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for BenchmarkRun {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("BenchmarkRun").unwrap()).clone()
    }
}

impl ::std::fmt::Display for BenchmarkRun {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BenchmarkRun {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:hw.trezor.messages.bitcoin.BenchmarkResult)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct BenchmarkResult {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.bitcoin.BenchmarkResult.value)
    pub value: ::std::option::Option<::std::string::String>,
    // @@protoc_insertion_point(field:hw.trezor.messages.bitcoin.BenchmarkResult.unit)
    pub unit: ::std::option::Option<::std::string::String>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.bitcoin.BenchmarkResult.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a BenchmarkResult {
    fn default() -> &'a BenchmarkResult {
        <BenchmarkResult as ::protobuf::Message>::default_instance()
    }
}

impl BenchmarkResult {
    pub fn new() -> BenchmarkResult {
        ::std::default::Default::default()
    }

    // optional string value = 1;

    pub fn value(&self) -> &str {
        match self.value.as_ref() {
            Some(v) => v,
            None => "",
        }
    }

    pub fn clear_value(&mut self) {
        self.value = ::std::option::Option::None;
    }

    pub fn has_value(&self) -> bool {
        self.value.is_some()
    }

    // Param is passed by value, moved
    pub fn set_value(&mut self, v: ::std::string::String) {
        self.value = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_value(&mut self) -> &mut ::std::string::String {
        if self.value.is_none() {
            self.value = ::std::option::Option::Some(::std::string::String::new());
        }
        self.value.as_mut().unwrap()
    }

    // Take field
    pub fn take_value(&mut self) -> ::std::string::String {
        self.value.take().unwrap_or_else(|| ::std::string::String::new())
    }

    // optional string unit = 3;

    pub fn unit(&self) -> &str {
        match self.unit.as_ref() {
            Some(v) => v,
            None => "",
        }
    }

    pub fn clear_unit(&mut self) {
        self.unit = ::std::option::Option::None;
    }

    pub fn has_unit(&self) -> bool {
        self.unit.is_some()
    }

    // Param is passed by value, moved
    pub fn set_unit(&mut self, v: ::std::string::String) {
        self.unit = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_unit(&mut self) -> &mut ::std::string::String {
        if self.unit.is_none() {
            self.unit = ::std::option::Option::Some(::std::string::String::new());
        }
        self.unit.as_mut().unwrap()
    }

    // Take field
    pub fn take_unit(&mut self) -> ::std::string::String {
        self.unit.take().unwrap_or_else(|| ::std::string::String::new())
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "value",
            |m: &BenchmarkResult| { &m.value },
            |m: &mut BenchmarkResult| { &mut m.value },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "unit",
            |m: &BenchmarkResult| { &m.unit },
            |m: &mut BenchmarkResult| { &mut m.unit },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<BenchmarkResult>(
            "BenchmarkResult",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for BenchmarkResult {
    const NAME: &'static str = "BenchmarkResult";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.value = ::std::option::Option::Some(is.read_string()?);
                },
                26 => {
                    self.unit = ::std::option::Option::Some(is.read_string()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.value.as_ref() {
            my_size += ::protobuf::rt::string_size(1, &v);
        }
        if let Some(v) = self.unit.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.value.as_ref() {
            os.write_string(1, v)?;
        }
        if let Some(v) = self.unit.as_ref() {
            os.write_string(3, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> BenchmarkResult {
        BenchmarkResult::new()
    }

    fn clear(&mut self) {
        self.value = ::std::option::Option::None;
        self.unit = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static BenchmarkResult {
        static instance: BenchmarkResult = BenchmarkResult {
            value: ::std::option::Option::None,
            unit: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for BenchmarkResult {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("BenchmarkResult").unwrap()).clone()
    }
}

impl ::std::fmt::Display for BenchmarkResult {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BenchmarkResult {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x18messages-benchmark.proto\x12\x1ahw.trezor.messages.bitcoin\x1a\rop\
    tions.proto\"\x14\n\x12BenchmarkListNames\"&\n\x0eBenchmarkNames\x12\x14\
    \n\x05names\x18\x01\x20\x03(\tR\x05names\"\"\n\x0cBenchmarkRun\x12\x12\n\
    \x04name\x18\x01\x20\x01(\tR\x04name\";\n\x0fBenchmarkResult\x12\x14\n\
    \x05value\x18\x01\x20\x01(\tR\x05value\x12\x12\n\x04unit\x18\x03\x20\x01\
    (\tR\x04unitBA\n#com.satoshilabs.trezor.lib.protobufB\x16TrezorMessageBe\
    nchmark\x80\xa6\x1d\x01\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(1);
            deps.push(super::options::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(4);
            messages.push(BenchmarkListNames::generated_message_descriptor_data());
            messages.push(BenchmarkNames::generated_message_descriptor_data());
            messages.push(BenchmarkRun::generated_message_descriptor_data());
            messages.push(BenchmarkResult::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}
