GO_KIND = ('golang_kind', """
enum golang_kind : uint8_t
{
  INVALID = 0x0,
  BOOL = 0x1,
  INT = 0x2,
  INT8 = 0x3,
  INT16 = 0x4,
  INT32 = 0x5,
  INT64 = 0x6,
  UINT = 0x7,
  UINT8 = 0x8,
  UINT16 = 0x9,
  UINT32 = 0xA,
  UINT64 = 0xB,
  UINTPTR = 0xC,
  FLOAT32 = 0xD,
  FLOAT64 = 0xE,
  COMPLEX64 = 0xF,
  COMPLEX128 = 0x10,
  ARRAY = 0x11,
  CHAN = 0x12,
  FUNC = 0x13,
  INTERFACE = 0x14,
  MAP = 0x15,
  PTR = 0x16,
  SLICE = 0x17,
  STRING = 0x18,
  STRUCT = 0x19,
  UNSAFEPTR = 0x1A,
  CHAN_DIRECTIFACE = 0x32,
  FUNC_DIRECTIFACE = 0x33,
  MAP_DIRECTIFACE = 0x35,
  STRUCT_DIRECTIFACE = 0x39,
};""")


GOLANG_TYPE = ('golang_type', """
struct golang_type
{
  int64_t size;
  int64_t ptrdata;
  uint32_t hash;
  uint8_t tflag;
  uint8_t align;
  uint8_t fieldalign;
  golang_kind kind;
  int64_t equal_fn;
  int64_t gcData;
  int32_t nameoff;
  int32_t typeoff;
};
""")
