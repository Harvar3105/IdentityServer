using System.Buffers.Binary;
using IdentityServer.Domain.Services;

namespace IdentityServer.Services;

public record ImageInfo(string ContentType, int Width, int Height);

// Detects the format by its signature and reads dimensions from the header; the client file name,
// extension and Content-Type are never trusted. Only the header is parsed, the image itself is not decoded.
public static class ImageInspector
{
  private static ReadOnlySpan<byte> PngSignature => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
  private static ReadOnlySpan<byte> JpegSignature => [0xFF, 0xD8, 0xFF];
  private static ReadOnlySpan<byte> RiffTag => "RIFF"u8;
  private static ReadOnlySpan<byte> WebpTag => "WEBP"u8;

  public static ImageInfo? Inspect(ReadOnlySpan<byte> data)
  {
    ImageInfo? info = null;
    if (data.StartsWith(PngSignature))
      info = ReadPng(data);
    else if (data.StartsWith(JpegSignature))
      info = ReadJpeg(data);
    else if (data.Length >= 12 && data.StartsWith(RiffTag) && data.Slice(8, 4).SequenceEqual(WebpTag))
      info = ReadWebp(data);

    return info is { Width: > 0, Height: > 0 } ? info : null;
  }

  private static ImageInfo? ReadPng(ReadOnlySpan<byte> data)
  {
    // The IHDR chunk must come first: length (4) + type (4) + width (4) + height (4).
    if (data.Length < 24 || !data.Slice(12, 4).SequenceEqual("IHDR"u8))
      return null;

    var width = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(16, 4));
    var height = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(20, 4));
    if (width > int.MaxValue || height > int.MaxValue)
      return null;

    return new ImageInfo(ImageContentTypes.Png, (int)width, (int)height);
  }

  private static ImageInfo? ReadJpeg(ReadOnlySpan<byte> data)
  {
    var position = 2;
    while (position < data.Length)
    {
      if (data[position] != 0xFF)
        return null;

      // Any number of 0xFF fill bytes may precede a marker.
      while (position < data.Length && data[position] == 0xFF)
        position++;
      if (position >= data.Length)
        return null;

      var marker = data[position++];

      // Standalone markers carry no length field.
      if (marker == 0x01 || marker is >= 0xD0 and <= 0xD7)
        continue;

      // Start of scan or end of image before a frame header means there are no dimensions to read.
      if (marker == 0xDA || marker == 0xD9 || marker == 0xD8)
        return null;

      if (position + 2 > data.Length)
        return null;
      var segmentLength = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(position, 2));
      if (segmentLength < 2 || position + segmentLength > data.Length)
        return null;

      // SOF0..SOF15 except DHT (C4), JPG (C8) and DAC (CC): length (2) + precision (1) + height (2) + width (2).
      if (marker is >= 0xC0 and <= 0xCF && marker != 0xC4 && marker != 0xC8 && marker != 0xCC)
      {
        if (segmentLength < 7)
          return null;

        var height = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(position + 3, 2));
        var width = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(position + 5, 2));
        return new ImageInfo(ImageContentTypes.Jpeg, width, height);
      }

      position += segmentLength;
    }

    return null;
  }

  private static ImageInfo? ReadWebp(ReadOnlySpan<byte> data)
  {
    // RIFF header (12) + chunk FourCC (4) + chunk size (4) + at least 10 bytes of the chunk payload.
    if (data.Length < 30)
      return null;

    var chunk = data.Slice(12, 4);
    var payload = data[20..];

    if (chunk.SequenceEqual("VP8 "u8))
    {
      // Lossy: 3-byte frame tag, start code 9D 01 2A, then 14-bit width and height.
      if (payload[3] != 0x9D || payload[4] != 0x01 || payload[5] != 0x2A)
        return null;

      var width = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(6, 2)) & 0x3FFF;
      var height = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(8, 2)) & 0x3FFF;
      return new ImageInfo(ImageContentTypes.Webp, width, height);
    }

    if (chunk.SequenceEqual("VP8L"u8))
    {
      // Lossless: signature 0x2F, then 14-bit (width - 1) and 14-bit (height - 1) packed little-endian.
      if (payload[0] != 0x2F)
        return null;

      var bits = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(1, 4));
      var width = (int)(bits & 0x3FFF) + 1;
      var height = (int)((bits >> 14) & 0x3FFF) + 1;
      return new ImageInfo(ImageContentTypes.Webp, width, height);
    }

    if (chunk.SequenceEqual("VP8X"u8))
    {
      // Extended: flags (1) + reserved (3), then 24-bit (canvas width - 1) and 24-bit (canvas height - 1).
      var width = ReadUInt24LittleEndian(payload.Slice(4, 3)) + 1;
      var height = ReadUInt24LittleEndian(payload.Slice(7, 3)) + 1;
      return new ImageInfo(ImageContentTypes.Webp, width, height);
    }

    return null;
  }

  private static int ReadUInt24LittleEndian(ReadOnlySpan<byte> bytes) =>
    bytes[0] | (bytes[1] << 8) | (bytes[2] << 16);
}
