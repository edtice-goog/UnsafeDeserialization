# Newtonsoft.Json `ToObject(Type)` with a data-supplied type name

A small, non-destructive harness that investigates whether Json.NET's
`JToken.ToObject(Type)` validates that its target type is a "plain old data"
(POD/DTO) type. **It does not.**

## What the harness does

`Program.cs` reads a JSON file that names its own CLR type in a `__type`
field, resolves it with `Type.GetType(...)`, and calls
`payload.ToObject(targetType)`. There is no allow-list and no POD check —
exactly the pattern a developer might write, and the one commercial static
analyzers tend not to flag.

`Gadgets.cs` defines:
- `BenignPayload` — a real DTO (the expected use).
- `SideEffectGadget` — a property **setter** with a side effect.
- `ConstructorGadget` — a **constructor** with a side effect.

The side effects are deliberately harmless: they print a warning and drop a
marker file in `%TEMP%`. They only prove that *our code ran because the
deserializer touched the object*.

## Build & run

No .NET SDK is required — this builds with the in-box .NET Framework compiler.

```powershell
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $csc /target:exe /out:UnsafeDeserialization.exe `
    /reference:lib\Newtonsoft.Json.dll Program.cs Gadgets.cs
Copy-Item lib\Newtonsoft.Json.dll .   # runtime dependency next to the exe

.\UnsafeDeserialization.exe sample_pod.json
.\UnsafeDeserialization.exe sample_setter_gadget.json
.\UnsafeDeserialization.exe sample_ctor_gadget.json
.\UnsafeDeserialization.exe sample_bcl_type.json
```

(`Newtonsoft.Json.dll` is v13.0.3, net45 build, extracted from the official
NuGet package.)

## Findings

1. **No POD/DTO check.** `ToObject(Type)` will instantiate and populate any
   type it can construct — DTOs, BCL collections (`List<string>` in
   `sample_bcl_type.json`), or behavior-bearing "gadget" classes alike.

2. **Constructors and property setters execute during deserialization.**
   Both gadgets ran their side-effecting code purely as a result of
   deserialization driven by attacker-controlled JSON.

3. **Why analyzers miss it.** The dangerous type name flows through ordinary
   application code (`Type.GetType`), not through a Json.NET feature the
   analyzer recognizes (`TypeNameHandling`, `$type`, `JsonSerializerSettings`).
   There is no tainted-Json.NET-setting for a rule to fire on.

## Important scope / severity nuance (read this)

This is **not** the same as the well-known
`TypeNameHandling.All`/`$type` remote-code-execution class, and it's
narrower than it might first appear:

- `ToObject(Type)` with default settings constructs **only the single type
  you name**, using its (usually parameterless) constructor plus writable
  members. It does **not** honor nested `$type` directives, so you cannot
  freely chain arbitrary gadget graphs the way `TypeNameHandling.All` allows.
- The attacker is therefore limited to types **already loadable in the
  process** whose *plain construction + simple property assignment* is itself
  harmful. That's a real attack surface (side-effecting setters/ctors,
  resource-exhaustion/DoS, types that touch the filesystem or network on
  construction), but it's a smaller set than full polymorphic gadget chains.
- Classic single-shot gadgets such as `ObjectDataProvider` typically need
  nested type handling to set their parameters, so they are *not* directly
  triggerable through a bare `ToObject` of one named type — though that
  depends on the gadget.

**Bottom line:** treating a data-supplied type name as input to
`Type.GetType` + `ToObject` is genuinely unsafe and analyzer-invisible, but
its severity is "attacker picks which already-loaded type gets constructed
and partially populated," not guaranteed RCE. The fix is the same either way.

## Mitigations

- Never derive the deserialization target type from the payload. Deserialize
  to a fixed, known DTO type chosen by the code.
- If polymorphism is required, resolve an attacker-supplied discriminator
  against a strict **allow-list** of vetted POD types — never via
  `Type.GetType`.
- Keep `TypeNameHandling = None` (the default) and, if you must use type
  handling, set a restrictive `SerializationBinder`.
- Consider a custom Roslyn analyzer that flags `Type.GetType(<tainted>)`
  feeding `ToObject`/`JsonConvert.DeserializeObject(_, Type)`.
