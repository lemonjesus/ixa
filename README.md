# ixa
`ixa` is a dumb, poorly written interactive (dis)assembler. Basically I wanted a dumb little tool where I could (dis)assemble one or two instructions in a complete vaccum with zero context for help with reverse engineering stuff. This is that tool.

## Build it
You can just use `make` to build it.

This library requires you have [Keystone](https://github.com/keystone-engine/keystone) for assembling and [Capstone](https://github.com/aquynh/capstone) for disassembling. You can install Capstone through a package manager:

```
$ sudo apt-get install libcapstone-dev
```

As for Keystone, you'll have to [build it from source](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE.md). It's inconvenient but not hard to do.

You'll also need GNU Readline. I installed it on my machine like this:

```
$ sudo apt-get install libreadline6 libreadline6-dev
```

## Use It
Using it is very easy. To assemble, use `a`:

```
> a inc eax; mov ax, bx
40 66 89 D8
```

To disassemble, use `d`:

```
> d 40 66 89 D8
inc     eax
mov     ax, bx
```

To change the platform you're (dis)assembling for, use `m`. You can use it interactively:

```
> m
select an arch:
 1 - X86
 2 - ARM
 3 - AArch64
 4 - MIPS
 5 - SPARC
choose: 2
select a mode:
 1 - ARM mode
 2 - THUMB mode (including Thumb-2)
 3 - ARMv8 A32 encodings for ARM
choose: 2
select an endian-ness:
 1 - little endian
 2 - big endian
choose: 1
```

or if you know the menu selections you want, you can just say:

```
> m 2 2 1
```

This program uses [`eval` by christian-vigh](https://github.com/christian-vigh/eval) to support the `c` command, which you can feed a math expression and evaluate it. See `eval`'s docs to see what you can put in. It's quite extensive:

```
> c 2 + ( log(127) / sqrt (5) )
Result = 4.16639
```

To convert a decimal number to hex, use `x`:
```
> x 105
0x69
```

## Future Work
I don't know if I'll spend the time to make it good. It works well enough for me for now, but it could certainly use some improvements:

 - ~~I feel like it's not a challenge to make it segfault~~ I've fixed some of these
 - I left out PPC support because the keystone header file said it wasn't supported. Is it really not supported?
 - ~~Allow for multi-line input (especially for `a`)~~ I've decided this is a bad idea.
 - ~~Have a command history (so when I press the up-key I don't get `^[[A`)~~ Fixed with GNU Readline
 - ~~Allow for keying through the current entry (so when I press the left-key I don't get `^[[D`)~~ Fixed with GNU Readline
 - Make the code overall... less trash
 - Separate it into files _I tried this, it didn't look pretty. Maybe later?_
 - Add some other small features so this can turn into a swiss army knife of sorts

Who knows if this list will ever get smaller.

## License

MIT License
