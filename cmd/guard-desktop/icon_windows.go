package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Small supersampled shield shared by the application and the real-state tray.
func shieldIcon(r, g, b byte) []byte {
	const size = 64
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	lines := [][4]float64{{32, 5, 54, 14}, {54, 14, 51, 37}, {51, 37, 43, 49}, {43, 49, 32, 58}, {32, 58, 21, 49}, {21, 49, 13, 37}, {13, 37, 10, 14}, {10, 14, 32, 5}, {21, 31, 29, 39}, {29, 39, 43, 24}}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			coverage := 0
			for sy := 0; sy < 4; sy++ {
				for sx := 0; sx < 4; sx++ {
					px, py := float64(x)+float64(sx)/4, float64(y)+float64(sy)/4
					for _, l := range lines {
						dx, dy := l[2]-l[0], l[3]-l[1]
						t := math.Max(0, math.Min(1, ((px-l[0])*dx+(py-l[1])*dy)/(dx*dx+dy*dy)))
						if math.Hypot(px-l[0]-t*dx, py-l[1]-t*dy) <= 2.2 {
							coverage++
							break
						}
					}
				}
			}
			img.SetNRGBA(x, y, color.NRGBA{r, g, b, uint8(coverage * 255 / 16)})
		}
	}
	var out bytes.Buffer
	_ = png.Encode(&out, img)
	return out.Bytes()
}
