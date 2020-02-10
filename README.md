# Spore Creation PNG Decoder - Python version
An old Spore PNG Decoder from 2008, by ymgve and rick. Minor edits by Kyle to make it work with the released version of the game.

This is provided largely for historical and reference purposes, but is fully functional for decoding almost any creations, from any version of Spore.

For a simple explanation of how the decoding process works, see here: http://www.rouli.net/2008/08/spores-png-format-illustrated.html

# Limitations
It does *not* work with adventures (they use a different format) - please use the newer .NET Core decoder for that.

Some overcomplex creations may not decode (will result in a gzip error), we believe this is due to the data being miss entirely from the PNG, and so this is unlikely to be fixable.

This python version was not developed by anyone currently involved with our projects, and we haven't fully tested all features of it. While PNG decoding does work, some of the other features may not be functional.

# Usage
This **requires Python 2**. Specifically, it is known to work on Python 2.7. Python 3 will not work.

Download the file, and use Python 2 to run it. Exact instructions will vary depending on how you have Python installed, whether you have installed both Python 2 and 3, etc...

Assuming Python 2 is on your PATH as `python2`, and your creation PNG file is `creationFile.png` you can run it by using:
```python2 spore_decoder_by_ymgve_and_rick.py creationFile.png```

This will decode the PNG, and create an xml file (with the same name as the creation's file) in the same directory.

# About the resulting XML file
The XML file has two main parts.

The first is the header, which contains metadata about the creation (name, asset ID, description, tags, author, parent creation, and various other internal data). The first section is *not* XML.

The second part is a proper XML document, containing the actual 3D model and paints. This includes all parts (rigblocks), their IDs, their location, and how they connect to each other.

You can see a simple C# class, which parses the entire first section, and retrieves the "part count" from the second section, here: https://github.com/Spore-Community/PNG-Analyzer-Discord-Bot/blob/master/Asset.cs
