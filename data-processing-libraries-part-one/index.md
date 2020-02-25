# Security of Data processing libraries Part 1 - Information gathering


Common feature for modern web applications to save and process user files. It can be a avatar generation, file thumbnails, reports or screenshot generation. Open source data processing libraries are usually used for such purposes. There are number of known vulnerabilities at those libraries that can be used to get access to the sensitive informtation. This article is mainly about a brief security review on Data processing libraries in last years.

<!--more-->

# Review Scope

This is not a complete review of all existing data processing libraries in a world (it will takes lots of time). Mostly I will focus on image processing libraries such as ImageMagick and GraphicsMagick. Couple words about libraries: ImageMagick is free software delivered as a ready-to-run binary distribution or as source code that you may use, copy, modify, and distribute in both open and proprietary. GraphicsMagick is a fork of ImageMagick, emphasizing stability of both programming API and command-line options. It was branched off ImageMagick's version 5.5.2 in 2002 after irreconcilable differences emerged in the developers' group applications. Both libraries have a common core of source code, but the devil is in the detail and the same exploit can not be reproduced at all libraries.

# Glossary

Before we start with code review let's start with features of ImageMagick & GraphicsMagick. If your are familiar with command line syntax of libraries you can skip this paragraph. There are two major command line utils commonly used at application level: identify and convert. Application (we will focus on web, but it is not limited) firstly tries to analyse file and then convert it to desired format and resolution. So what is identify command line utility?

- The identify program describes the format and characteristics of one or more image files. It also reports if an image is incomplete or corrupt. The information returned includes the image number, the file name, the width and height of the image, whether the image is colormapped or not, the number of colors in the image, the number of bytes in the image, the format of the image (JPEG, PNM, etc.), and finally the number of seconds it took to read and process the image. ImageMagick identify [man](https://imagemagick.org/script/identify.php) page.

> Delegate - program that used by library to process specific file format.

Common usage of library looks like:

```bash
λ identify -version                                               
Version: ImageMagick 7.0.9-8 Q16 x86_64 2019-12-09 https://imagemagick.org
Copyright: © 1999-2020 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI Modules OpenMP(3.1) 
Delegates (built-in): bzlib freetype heic jng jp2 jpeg lcms ltdl lzma openexr png tiff webp xml zlib

λ identify ~/Dropbox/DataProcessing/IM_memory_read/10.xbm
/Users/doge/DataProcessing/IM_memory_read/10.xbm XBM 128x128 128x128+0+0 8-bit sRGB 2c 8531B 0.000u 0:00.000
```
There are two usually commonly used outputs file format and file dimension: `XBM` and `128x128` at example.

- The convert program used to convert between image formats as well as resize an image, blur, crop, despeckle, dither, draw on, flip, join, re-sample, and much more. [man](https://imagemagick.org/script/convert.php) page.

Common (_vulnerable_) usage of library looks like:
```bash
λ convert input.gif outpu.png

λ identify sample.png  
output.png PNG 600x400 600x400+0+0 8-bit sRGB 47c 24792B 0.000u 0:00.001
```

GraphicsMagick have almost the same syntax. 

```bash
gm identify file [ file ... ]
```

GraphicsMagick identify [man](http://www.graphicsmagick.org/identify.html) page.

```bash
gm convert [ options ... ] input_file [ options ... ] output_file
```

GraphicsMagick convert [man](http://www.graphicsmagick.org/convert.html) page.

### Security of ImageMagick
There is special [security policy](https://imagemagick.org/script/security-policy.php) that you can configure to meet your requirements. User can disable special coders (file formats).
Example of policy looks like:
```xml
<policymap>
  <!-- temporary path must be a preexisting writable directory -->
  ...
  <policy domain="coder" rights="none" pattern="MVG" />
  <policy domain="coder" rights="none" pattern="EPS" />
  <policy domain="coder" rights="none" pattern="PS" />
  <policy domain="coder" rights="none" pattern="PS2" />
  <policy domain="coder" rights="none" pattern="PS3" />
  <policy domain="coder" rights="none" pattern="PDF" />
  <policy domain="coder" rights="none" pattern="XPS" />
  <policy domain="filter" rights="none" pattern="*" />
  <policy domain="delegate" rights="none" pattern="HTTPS" />  
  <policy domain="delegate" rights="none" pattern="SHOW" />
  <policy domain="delegate" rights="none" pattern="WIN" />
  <policy domain="path" rights="none" pattern="@*"/>  
```

You can check you current policy configuration:
```bash
λ identify -list policy

Path: /etc/ImageMagick-6/policy.xml
  Policy: undefined
    rights: None 
  Policy: Coder
    rights: None 
    pattern: EPHEMERAL
  Policy: Coder
    rights: None 
    pattern: URL
  Policy: Coder
    rights: None 
    pattern: HTTPS
  ...
```

### Security of GraphicsMagick

There is special environment variable MAGICK_CODER_STABILITY to constrain the supported file formats to the subsets selected by PRIMARY or STABLE. After setting this environment variable (e.g. export MAGICK_CODER_STABILITY=PRIMARY), use gm convert -list format and verify that the format support you need is enabled. Selecting the PRIMARY or STABLE options blocks access of http and ftp URLs (SSRF vulnerability), but does not block SVG renderer access to read local image files. [man](http://www.graphicsmagick.org/security.html) page.

# Passive scan

To indentify what kind of data processing library are used at testing backend we can use set of sample images that are process differently. That will take lot of eforts from your side. Sometimes this process can be simplified by passive scan of image files metadata. 

### Image Metadata 

There are number of image metadata standart used today:
- Exchangeable image file format [Exif](https://en.wikipedia.org/wiki/Exif)
- Extensible Metadata Platform [XMP](https://en.wikipedia.org/wiki/Extensible_Metadata_Platform) metadata is XML document that can be exploited by [oxml_xxe](https://github.com/BuffaloWill/oxml_xxe) tool. You can find more details at BuffaloWill [presentation](http://oxmlxxe.github.io/reveal.js/slides.html#/)
- PNG iTXt, tEXt, zTXt chunks. The iTXt, tEXt, and zTXt chunks (text chunks) are used for conveying textual information associated with the image. They are the places we can find all metadata of PNG file. Each of the text chunks contains as its first field a keyword that indicates the type of information represented by the text string.

PNG iTXt, tEXt, zTXt chunks can be easely used for information gathering. For example PNG image metadata can be extracted by ImageMagick identify command tool:
```bash
λ identify -verbose output.png 
...
Properties:
    date:create: 2020-02-25T13:44:44+01:00
    date:modify: 2020-02-25T13:44:44+01:00
    png:bKGD: chunk was found (see Background color, above)
    png:cHRM: chunk was found (see Chromaticity, above)
    png:gAMA: gamma=0.45454544 (See Gamma, above)
    png:IHDR.bit-depth-orig: 16
    png:IHDR.bit_depth: 16
    png:IHDR.color-type-orig: 6
    png:IHDR.color_type: 6 (RGBA)
    png:IHDR.interlace_method: 0 (Not interlaced)
    png:IHDR.width,height: 884, 945
    png:pHYs: x_res=90, y_res=90, units=0
    png:sRGB: intent=0 (Perceptual Intent)
    png:text: 3 tEXt/zTXt/iTXt chunks were found
    png:tIME: 2020-02-25T12:44:44Z
    signature: a3ac10ba63ea8307b3603ed1fdb484159dabeaf64714d2d7044705bcc636a8fc
    svg:base-uri: file:///tmp/magick-21944uuDJ1rcgBBRP
...
```
Let's take a close look at _svg:base-uri:_ property. It will contains interesting information. It can be used to number of purposes. First of all vulnerable software disclosure sensitive inrotmation - full path to temp folder used for image conversation. This vulnerability firstly was discovered by black box testing and it takes a while to identify affected software. 

### ImageMagick info disclosure SVG coder

Vulnerable code ImageMagick before 7.0.5-5. [Commit](https://github.com/ImageMagick/ImageMagick/commit/cab049cec5034813efc221425aff2ce6a6bcb896) Library _librsvg_ used by ImageMagick as delegate at SVG coder.

> Coder - image processing library component used for file.

__librsvg__ is a free software SVG rendering library written as part of the GNOME project, intended to be lightweight and portable. The Linux command-line program rsvg uses the library to turn SVG files into raster images. Function rsvg_handle_get_base_uri returns the base uri, possibly null. SVG coder set property `svg:base-uri` with detalied information about source file full path.
This vulnerability was not fixed at 6 version of ImageMagick and could be exploited with PES coder as well as SVG. PES coder use SVG for file processing. As SVG it is vulnerable to information disclosure. This feature could be usefull for attacker in case SVG files are disabled at web server. 

> Note! GraphicsMagick uses own svg parser and does not vulnerable. Image metadata could be used to get access to sensitive information at GraphicsMagick by active scan as it will shown later.

### ImageMagick info disclosure thumbnail generator

Plugin Burp and ZAP proxy [Image Metadata](https://github.com/PortSwigger/image-metadata) allows to extract metadata from images. It support two types of metadata: JPEG [Exif](https://en.wikipedia.org/wiki/Exif) and PNG [Text chunks](https://www.w3.org/TR/PNG-Chunks.html#C.tEXt). Ahri discovered that image property Thumb can be used for information gathering, but vulnerabilty was not fixed by ImageMagick team. Vulnerable code can be found at [github](https://github.com/ImageMagick/ImageMagick/blob/92a873d0873534bc6ad50e5509709919dccfbdb4/MagickCore/resize.c#L3738) The example of vulnerable usage of library:

```bash
λ convert /home/doge/output.png -thumbnail 64x64 output.png 
...
λ identify -verbose output.png
...
Properties:
    date:create: 2020-02-25T14:36:34+01:00
    date:modify: 2020-02-25T14:36:34+01:00
    png:bKGD: chunk was found (see Background color, above)
    png:cHRM: chunk was found (see Chromaticity, above)
    png:gAMA: gamma=0.45454544 (See Gamma, above)
    png:IHDR.bit-depth-orig: 8
    png:IHDR.bit_depth: 8
    png:IHDR.color-type-orig: 6
    png:IHDR.color_type: 6 (RGBA)
    png:IHDR.interlace_method: 0 (Not interlaced)
    png:IHDR.width,height: 60, 64
    png:pHYs: x_res=90, y_res=90, units=0
    png:sRGB: intent=0 (Perceptual Intent)
    png:text: 11 tEXt/zTXt/iTXt chunks were found
    png:tIME: 2020-02-25T13:36:34Z
    signature: 2ef76784e8d9b4cd169c17efd47a82113c9c9ef102bbde85c926af4ddad6b99b
    software: ImageMagick 6.8.9-9 Q16 x86_64 2019-11-12 http://www.imagemagick.org
    Thumb::Document::Pages: 1
    Thumb::Image::Height: 945
    Thumb::Image::Width: 884
    Thumb::Mimetype: image/png
    Thumb::MTime: 1582634684
    Thumb::Size: 654KBB
    Thumb::URI: file:///home/doge/test.png
...
```

> Note! GraphicsMagick does not add image properties `Thumb::`

# TO DO

You can find all payloads at Github [repository](https://github.com/d0ge/data-processing)

# Acknowledgement

Thanks ImageMagick and GraphicsMagick teams for the coordination and bug fixing! 
