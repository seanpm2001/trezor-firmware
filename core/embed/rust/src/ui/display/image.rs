use crate::{io::BinaryData, ui::geometry::Offset};

struct BinaryDataReader<'a> {
    data: BinaryData<'a>,
    ofs: usize,
}

impl<'a> BinaryDataReader<'a> {
    pub fn new(data: BinaryData<'a>) -> Self {
        Self { data, ofs: 0 }
    }

    pub fn read(&mut self, dest: &mut [u8]) -> Option<usize> {
        let len = self.data.read(self.ofs, dest);
        self.ofs += len;
        if len == dest.len() {
            Some(len)
        } else {
            None
        }
    }

    pub fn skip(&mut self, len: usize) -> Option<usize> {
        self.ofs += len;
        Some(len)
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        let mut buff: [u8; 1] = [0; 1];
        self.read(&mut buff)?;
        Some(buff[0])
    }

    pub fn read_u16_le(&mut self) -> Option<u16> {
        let mut buff: [u8; 2] = [0; 2];
        self.read(&mut buff)?;
        Some(u16::from_le_bytes(buff))
    }

    pub fn read_u16_be(&mut self) -> Option<u16> {
        let mut buff: [u8; 2] = [0; 2];
        self.read(&mut buff)?;
        Some(u16::from_be_bytes(buff))
    }

    pub fn read_u32_le(&mut self) -> Option<u32> {
        let mut buff: [u8; 4] = [0; 4];
        self.read(&mut buff)?;
        Some(u32::from_le_bytes(buff))
    }
}

#[derive(PartialEq, Debug, Eq, FromPrimitive, Clone, Copy)]
pub enum ToifFormat {
    FullColorBE = 0, // big endian
    GrayScaleOH = 1, // odd hi
    FullColorLE = 2, // little endian
    GrayScaleEH = 3, // even hi
}

pub struct ToifInfo {
    format: ToifFormat,
    size: Offset,
    len: usize,
}

impl ToifInfo {
    pub const HEADER_LENGTH: usize = 12;

    pub fn parse(image: BinaryData) -> Option<Self> {
        let mut reader = BinaryDataReader::new(image);
        if reader.read_u8()? != b'T' && reader.read_u8()? != b'O' && reader.read_u8()? != b'I' {
            return None;
        }

        let format = match reader.read_u8()? {
            b'f' => ToifFormat::FullColorBE,
            b'g' => ToifFormat::GrayScaleOH,
            b'F' => ToifFormat::FullColorLE,
            b'G' => ToifFormat::GrayScaleEH,
            _ => return None,
        };

        let width = reader.read_u16_le()?;
        let height = reader.read_u16_le()?;
        let len = reader.read_u32_le()? as usize;

        if width > 1024 || height > 1024 || len > 65536 {
            return None;
        }

        if len + Self::HEADER_LENGTH != image.len() {
            return None;
        }

        Some(Self {
            format,
            size: Offset::new(width as i16, height as i16),
            len,
        })
    }

    pub fn format(&self) -> ToifFormat {
        self.format
    }

    pub fn size(&self) -> Offset {
        self.size
    }

    pub fn width(&self) -> i16 {
        self.size.x
    }

    pub fn height(&self) -> i16 {
        self.size.y
    }

    pub fn is_grayscale(&self) -> bool {
        matches!(
            self.format,
            ToifFormat::GrayScaleOH | ToifFormat::GrayScaleEH
        )
    }

    pub fn stride(&self) -> usize {
        if self.is_grayscale() {
            (self.width() + 1) as usize / 2
        } else {
            self.width() as usize * 2
        }
    }
}

pub struct JpegInfo {
    size: Offset,
    mcu_height: i16,
}

impl JpegInfo {
    pub fn parse(image: BinaryData) -> Option<Self> {
        const M_SOI: u16 = 0xFFD8;
        const M_SOF0: u16 = 0xFFC0;
        const M_DRI: u16 = 0xFFDD;
        const M_RST0: u16 = 0xFFD0;
        const M_RST7: u16 = 0xFFD7;
        const M_SOS: u16 = 0xFFDA;
        const M_EOI: u16 = 0xFFD9;

        let mut result = None;
        let mut reader = BinaryDataReader::new(image);

        while reader.read_u16_be()? != M_SOI {}

        loop {
            let marker = reader.read_u16_be()?;

            if (marker & 0xFF00) != 0xFF00 {
                return None;
            }

            match marker {
                M_SOI => (),
                M_SOF0 => {
                    let pos = reader.ofs;
                    let len = reader.read_u16_be()? as usize;
                    let _prec = reader.read_u8()?;
                    let w = reader.read_u16_be()? as i16;
                    let h = reader.read_u16_be()? as i16;
                    // Number of components
                    let nc = reader.read_u8()?;
                    if (nc != 1) && (nc != 3) {
                        return None;
                    }
                    // id of first component
                    let _id1 = reader.read_u8()?;
                    // Sampling factor of the first component
                    let c1 = reader.read_u8()?;
                    if (c1 != 0x11) && (c1 != 0x21) & (c1 != 0x22) {
                        return None;
                    };
                    let mcu_height = (8 * (c1 & 15)) as i16;
                    result = Some(JpegInfo {
                        size: Offset::new(w, h),
                        mcu_height,
                    });

                    reader.ofs = pos + len;
                }
                M_DRI => {
                    reader.skip(4);
                }
                M_EOI => return None,
                M_RST0..=M_RST7 => (),
                M_SOS => break,
                _ => {
                    let len = reader.read_u16_be()? as usize;
                    reader.skip(len);
                }
            }
        }

        result
    }

    pub fn size(&self) -> Offset {
        self.size
    }

    pub fn width(&self) -> i16 {
        self.size.x
    }

    pub fn height(&self) -> i16 {
        self.size.y
    }

    pub fn mcu_height(&self) -> i16 {
        self.mcu_height
    }
}

pub enum ImageInfo {
    Invalid,
    Toif(ToifInfo),
    Jpeg(JpegInfo),
}

impl ImageInfo {
    pub fn parse(image: BinaryData) -> Self {
        if let Some(info) = ToifInfo::parse(image) {
            Self::Toif(info)
        } else if let Some(info) = JpegInfo::parse(image) {
            Self::Jpeg(info)
        } else {
            Self::Invalid
        }
    }
}
