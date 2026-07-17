import AppKit

guard CommandLine.arguments.count == 2 else {
    fputs("usage: generate-icon.swift <output.png>\n", stderr)
    exit(2)
}

let size = NSSize(width: 1024, height: 1024)
let image = NSImage(size: size)
image.lockFocus()

NSColor.clear.setFill()
NSRect(origin: .zero, size: size).fill()

let backgroundRect = NSRect(x: 64, y: 64, width: 896, height: 896)
let background = NSBezierPath(roundedRect: backgroundRect, xRadius: 208, yRadius: 208)
NSColor(calibratedRed: 0.10, green: 0.12, blue: 0.14, alpha: 1).setFill()
background.fill()

if let symbol = NSImage(systemSymbolName: "hand.point.up.left.fill", accessibilityDescription: nil) {
    let symbolConfig = NSImage.SymbolConfiguration(pointSize: 460, weight: .semibold)
        .applying(.init(hierarchicalColor: NSColor(calibratedRed: 1.0, green: 0.56, blue: 0.16, alpha: 1)))
    let configured = symbol.withSymbolConfiguration(symbolConfig) ?? symbol
    configured.draw(in: NSRect(x: 232, y: 246, width: 560, height: 560))
}

let statusDot = NSBezierPath(ovalIn: NSRect(x: 714, y: 174, width: 142, height: 142))
NSColor(calibratedRed: 0.20, green: 0.78, blue: 0.46, alpha: 1).setFill()
statusDot.fill()

image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:]) else {
    fputs("could not render icon\n", stderr)
    exit(1)
}

try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]), options: .atomic)
