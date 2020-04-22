### Adding Bugs

To add a new bug to an existing library, create a patch and add it to
`targets/$LIBRARY/patches/bugs` for the corresponding library.

To create a patch, you need to use the following flags:
* `MAGMA_ENABLE_FIXES`: if defined at compile time, only the non-buggy code is
  run, i.e the patch doesn't change anything to the actual library
* `MAGMA_ENABLE_CANARIES` : if defined at compile time, canaries are enabled and
  the buggy code should run. You should also insert an "oracle" that will report
  when the bug is **Reached** and **Triggered**

An "oracle" is a call to the Magma function :
```
MAGMA_LOG(char * bug_identifier, bool trigger_condition)

```

If the trigger condition contains logical operators `AND (&&)` or `OR (||)`,
you should use `MAGMA_AND(e1,e2)` and `MAGMA_OR(e1,e2)`.

This avoids the creation of new branches from short-compiler behavior by using bitwise operation.

Once you have implemented your bug with the correct trigger condition you can create a new patch file named `bug_identifier.patch`  
Also your patch must not contain an empty line at the end otherwise your patch won't be able to be applied. A simple way of avoiding this is to use
```
git diff>./PATH
```

Patches that implement a bug that is not triggerable can be moved to `targets/$LIBRARY/patches/graveyard`

Please provide as well the following informations about the bug:

* CVE ID
* The vulnerability type (e.g. Heap-buffer overflow, 0-pointer dereference)
* The component
* The bug identifier (e.g. Bug RAM042)
* The link/s to the bug report/s
* The link/s to the fix/es
* Any useful comments (e.g. bug only works for 32-bit machine)

Note: please provide those informations even if a bug couldn't be implemented and state in the comments why it couldn't be implemented (e.g. code disappeared).

## Warnings

Be careful about the following things before making a pull request:

* The validity of your patch
* Try as well to apply the patch and compile the library you are working on
* Do not add any side effects
