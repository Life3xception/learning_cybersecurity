# Malicious Document Analysis

## CyberChef

CyberChef is a web-based application - used to slice, dice, encode, decode, parse and analyze data or files. It uses functions, also known as recipes, to analyze the malicious document or the supsicious data.

For example, here are some recipes and their functionality:

- `strings`: extracts the strings from a given file.
- `Find / Replace`: useful to remove pattern that attackers often add to obfuscate the actual value.
- `Drop bytes`: removes bytes from the output (i.e. when there are extra bytes).
- `From base64`: decodes the input which is base64 encoded.
- `Decode text`: useful to decode the input into a specified encoding (i.e. UTF-8).
- `Extract URLs`: extracts the URLs from the result.
- `Split`: splits the input into strings based on a given sequence of characters.
- `Defang URLs`: dafanging urls makes them unclickable, useful to avoid accidental clicks.
