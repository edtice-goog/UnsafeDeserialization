using System;
using System.Collections.Generic;
using System.Reflection;
using Newtonsoft.Json.Linq;

namespace UnsafeDeserialization
{
    // =====================================================================
    //  Test bed for the AUDIT checker
    //  (DF.NEWTONSOFT_TYPE_DESERIALIZATION_AUDIT).
    //
    //  Program.cs demonstrates the *precise* pattern: a distrusted input
    //  flows through Type.GetType into ToObject. That fires both the
    //  precise checker and the audit checker.
    //
    //  This file demonstrates cases the AUDIT checker should catch but
    //  the PRECISE checker should not -- there is no distrusted-input
    //  path, only a reflection-derived Type reaching the sink. The
    //  methods below are never called; Coverity still analyzes them.
    //
    //  Legend
    //     [SAFE]  neither checker should fire
    //     [AUDIT] only DF.NEWTONSOFT_TYPE_DESERIALIZATION_AUDIT should fire
    //     [BOTH]  both fire (present in Program.cs -- not repeated here)
    //
    //  Run:
    //     cov-analyze --dir idir --all --distrust-all ^
    //         --enable DF.NEWTONSOFT_TYPE_DESERIALIZATION ^
    //         --enable DF.NEWTONSOFT_TYPE_DESERIALIZATION_AUDIT ^
    //         --directive-file newtonsoft_unsafe_deserialization.json ^
    //         --directive-file newtonsoft_unsafe_deserialization_audit.json
    // =====================================================================
    public static class AuditProgram
    {
        private static readonly object s_prototype = new BenignPayload();

        // -----------------------------------------------------------------
        // [SAFE] Generic overload. No Type argument at all -- neither
        // checker can fire on a call that does not match the sink's
        // signature.
        // -----------------------------------------------------------------
        public static object Safe_GenericOverload(JToken payload)
        {
            return payload.ToObject<BenignPayload>();
        }

        // -----------------------------------------------------------------
        // [SAFE] typeof(T) compiles to Type.GetTypeFromHandle(handle),
        // which we deliberately do NOT seed. So the Type reaches ToObject
        // untainted. Neither checker fires.
        // -----------------------------------------------------------------
        public static object Safe_Typeof(JToken payload)
        {
            return payload.ToObject(typeof(BenignPayload));
        }

        // -----------------------------------------------------------------
        // [AUDIT] Type.GetType() with a HARDCODED literal string.
        //
        //   Precise: the literal string is untainted, the Type.GetType
        //     propagator produces an untainted Type -> does not fire.
        //   Audit  : Type.GetType is a seeded source under source_code
        //     -> its return is tainted -> reaches ToObject -> fires.
        //
        // Represents the "no allow-list, but the type name is at least
        // hard-coded" case. Still worth reviewing: a literal type name
        // bypasses whatever runtime allow-list the app might have.
        // -----------------------------------------------------------------
        public static object Audit_TypeGetTypeLiteral(JToken payload)
        {
            Type t = Type.GetType("System.Collections.Generic.List`1[[System.String]]");
            return payload.ToObject(t);
        }

        // -----------------------------------------------------------------
        // [AUDIT] object.GetType() returns the runtime type of an
        // existing object. Seeded because that runtime type could be any
        // subclass loaded into the process.
        // -----------------------------------------------------------------
        public static object Audit_ObjectGetType(JToken payload)
        {
            Type t = s_prototype.GetType();
            return payload.ToObject(t);
        }

        // -----------------------------------------------------------------
        // [AUDIT] typeof(T).BaseType -- reflection graph walking.
        //
        //   Precise: no distrusted input touches this Type.
        //   Audit  : System.Type::get_BaseType is seeded -> fires.
        // -----------------------------------------------------------------
        public static object Audit_BaseType(JToken payload)
        {
            Type t = typeof(BenignPayload).BaseType;
            return payload.ToObject(t);
        }

        // -----------------------------------------------------------------
        // [AUDIT] Type.MakeGenericType() constructs a Type from parts at
        // runtime. Even when all parts are typeof(T), the composed Type
        // has been synthesized reflectively.
        // -----------------------------------------------------------------
        public static object Audit_MakeGenericType(JToken payload)
        {
            Type t = typeof(List<>).MakeGenericType(typeof(string));
            return payload.ToObject(t);
        }

        // -----------------------------------------------------------------
        // [AUDIT] Assembly.GetType(literal) -- symmetric to
        // Type.GetType(literal), same audit rationale.
        // -----------------------------------------------------------------
        public static object Audit_AssemblyGetType(JToken payload)
        {
            Assembly a = typeof(AuditProgram).Assembly;
            Type t = a.GetType("UnsafeDeserialization.BenignPayload");
            return payload.ToObject(t);
        }

        // -----------------------------------------------------------------
        // [AUDIT] Assembly.GetTypes() bulk enumeration. Whatever the
        // index resolves to, it came from a reflective enumeration --
        // an attacker who can influence the index (or the assembly's
        // type ordering) picks the target.
        // -----------------------------------------------------------------
        public static object Audit_AssemblyGetTypes(JToken payload)
        {
            Type[] all = typeof(AuditProgram).Assembly.GetTypes();
            return payload.ToObject(all[0]);
        }

        // -----------------------------------------------------------------
        // [AUDIT] The "chain through a local" case. The audit checker
        // should still flag it -- taint on a seeded Type flows through
        // ordinary assignment.
        // -----------------------------------------------------------------
        public static object Audit_ThroughLocal(JToken payload)
        {
            Type resolved = Type.GetType("System.String");
            Type stashed  = resolved;
            return payload.ToObject(stashed);
        }
    }
}
