"""keyRX mark - the PIL capsule used by the banner and OG generators.

logo.svg is the authored source of the mark. Since 2026-08-18 every logo-*.png
and avatar-*.png is Chromium's rasterisation of that SVG (assets/render_svg.cjs,
alpha kept, hole and teeth cut through) - one source, no drift. This file draws
the same capsule with PIL (cylinder shading, rim, countersunk bow hole, two
clipped teeth) for the X header and the OG image, where the mark sits inside a
composed picture. Fonts are not committed; the banner uses the same face the
site embeds as a subset (needs Pillow + the JetBrains Mono TTF).
"""
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageChops
BLUE=(90,166,201); BLUE_D=(40,96,128); BLUE_L=(150,208,232); AMBER=(201,151,79); AMBER_D=(132,92,40); AMBER_L=(238,204,140)
FIELD=(9,18,40); WHITE=(219,227,242)
SS=4
def pill_mask(W,H,x0,y0,w,h):
    m=Image.new('L',(W,H),0); ImageDraw.Draw(m).rounded_rectangle([x0,y0,x0+w,y0+h],radius=h//2,fill=255); return m
def vgrad(w,h,stops):
    g=Image.new('RGB',(1,h)); px=g.load()
    for y in range(h):
        t=y/max(1,h-1); i=min(int(t*(len(stops)-1)),len(stops)-2); lt=t*(len(stops)-1)-i
        a,b=stops[i],stops[i+1]; px[0,y]=tuple(int(a[k]+(b[k]-a[k])*lt) for k in range(3))
    return g.resize((w,h))
def capsule(W,H,x0,y0,w,h,teeth_n=2,seam_gap=0.30,imprint=False,shadow=True):
    """Rendered capsule key on a WxH RGBA canvas. teeth_n teeth, first tooth
    starts seam_gap*h after the seam band; all cuts clipped to the pill."""
    def layer(): return Image.new('RGBA',(W,H),(0,0,0,0))
    im=layer(); pm=pill_mask(W,H,x0,y0,w,h)
    if shadow:
        sh=layer(); ImageDraw.Draw(sh).rounded_rectangle([x0+5*SS,y0+11*SS,x0+w+5*SS,y0+h+11*SS],radius=h//2,fill=(1,4,14,180))
        sh=sh.filter(ImageFilter.GaussianBlur(10*SS)); im=Image.alpha_composite(im,sh)
    body=layer()
    gb=vgrad(w,h,[BLUE_L,BLUE,BLUE_D]).convert('RGBA'); ga=vgrad(w,h,[AMBER_L,AMBER,AMBER_D]).convert('RGBA')
    body.paste(gb,(x0,y0)); body.paste(ga.crop((w//2,0,w,h)),(x0+w//2,y0))
    body.putalpha(ImageChops.multiply(body.split()[3],pm)); im=Image.alpha_composite(im,body)
    hl=layer(); ImageDraw.Draw(hl).rounded_rectangle([x0+h*0.16,y0+h*0.10,x0+w-h*0.16,y0+h*0.30],radius=h*0.10,fill=(255,255,255,95))
    hl=hl.filter(ImageFilter.GaussianBlur(3*SS)); hl.putalpha(ImageChops.multiply(hl.split()[3],pm)); im=Image.alpha_composite(im,hl)
    rim=layer(); ImageDraw.Draw(rim).rounded_rectangle([x0,y0,x0+w,y0+h],radius=h//2,outline=(255,255,255,55),width=2*SS)
    rim.putalpha(ImageChops.multiply(rim.split()[3],pm)); im=Image.alpha_composite(im,rim)
    d=ImageDraw.Draw(im)
    bx=x0+w//2; d.rectangle([bx-3*SS,y0,bx+3*SS,y0+h],fill=(20,32,60,200)); d.rectangle([bx-1*SS,y0,bx+1*SS,y0+h],fill=(255,255,255,40))
    hr=int(h*0.22); hx=x0+int(w*0.24); hy=y0+h//2
    d.ellipse([hx-hr-4*SS,hy-hr-4*SS,hx+hr+4*SS,hy+hr+4*SS],fill=BLUE_D+(255,))
    d.ellipse([hx-hr,hy-hr,hx+hr,hy+hr],fill=FIELD+(255,))
    d.arc([hx-hr,hy-hr,hx+hr,hy+hr],start=200,end=340,fill=(255,255,255,70),width=2*SS)
    teeth=layer(); td=ImageDraw.Draw(teeth)
    tw=int(h*0.15); gap=int(h*0.12)
    tx=bx+3*SS+int(h*seam_gap)
    heights=[int(h*0.38),int(h*0.54),int(h*0.30)][:teeth_n]
    for th in heights:
        td.rectangle([tx-2*SS,y0+h-th-2*SS,tx+tw+2*SS,y0+h+8*SS],fill=AMBER_D+(255,))
        td.rectangle([tx,y0+h-th,tx+tw,y0+h+8*SS],fill=FIELD+(255,))
        td.rectangle([tx+tw,y0+h-th,tx+tw+1*SS,y0+h+8*SS],fill=(255,255,255,50)); tx+=tw+gap
    teeth.putalpha(ImageChops.multiply(teeth.split()[3],pm)); im=Image.alpha_composite(im,teeth)
    if imprint:
        f=ImageFont.truetype('jbmono.ttf',int(h*0.34))
        tx2=hx+hr+int(h*0.18); ty=y0+int(h*0.30)
        d.text((tx2+1*SS,ty+1*SS),"RX",font=f,fill=(255,255,255,45)); d.text((tx2,ty),"RX",font=f,fill=(24,60,90,230))
    return im
