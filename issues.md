# Known Issues

## libxml2 Include Path Issue

**Status:** Workaround applied locally; needs permanent fix in `sindarin-pkg-libs`

**Symptom:**
`make test` fails with `test_xml` showing a compile error:
```
fatal error: libxml/parser.h: No such file or directory
```

**Root Cause:**
The `sindarin-pkg-libs` package installs libxml2 headers via vcpkg, which places them at:
```
libs/linux/include/libxml2/libxml/*.h
```

However, the standard include directive is `#include <libxml/parser.h>`, which expects headers at:
```
libs/linux/include/libxml/*.h
```

This is a known quirk with vcpkg's libxml2 packaging - it requires adding `include/libxml2` to the compiler's include path.

**Workaround:**
Create a symlink in the package's include directory:
```bash
ln -s libxml2/libxml .sn/sindarin-pkg-libs/libs/linux/include/libxml
```

**Permanent Fix:**
The `sindarin-pkg-libs` repository should be updated to include this symlink for all platforms:
- `libs/linux/include/libxml -> libxml2/libxml`
- `libs/darwin/include/libxml -> libxml2/libxml`
- `libs/windows/include/libxml -> libxml2/libxml`

This could be added to the build scripts or as a post-install step.
