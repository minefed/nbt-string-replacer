# nbt-string-replacer

Rust-based CLI tool used for bulk modification of strings within NBT data in Minecraft worlds.

## How to use?

```shell
nbt-string-replacer [WORLD PATH] [OLD STRING] [NEW STRING]
```

- [WORLD PATH]
  - This is the path to the Minecraft world. Both absolute and relative paths are supported.
- [OLD STRING]
  - This is the string to be modified.
- [NEW STRING]
  - Replacement string.

To change the string “OLD” to “NEW” in the ./world folder, use the following command:

```shell
nbt-string-replacer ./world "OLD" "NEW"
```