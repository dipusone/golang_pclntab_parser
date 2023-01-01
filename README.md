# GoLang pclntab parser
Author: **Jacopo Ferrigno**

_BinaryNinja plugin to parse gopclntab and restore functions names for all GoLang versions._

## Description:

This plugin will parse the gopclntab and restore the function names extracting the information from the `.gopclntab` section in the binary. If there is no section named .gopclntab it will try to search for the section.

The plugin works for all GoLang version from 12 to 119.

## References

The plugin is based on the following resources.

	https://github.com/f0rki/bn-goloader
	https://go.dev/src/debug/gosym/pclntab.go
	https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub


## License

This plugin is released under an [MIT license](./license).
