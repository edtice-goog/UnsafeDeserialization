using System;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace UnsafeDeserialization
{
    // =====================================================================
    //  The vulnerable reader.
    //
    //  This is the pattern under investigation: a JSON document tells us
    //  *which CLR type* it wants to be deserialized into (the "__type"
    //  field), and we obligingly resolve that type name and hand it to
    //  Newtonsoft's JToken.ToObject(Type). Static analyzers tend not to
    //  flag this because, unlike TypeNameHandling/$type, the dangerous
    //  type name flows in through ordinary application code (Type.GetType)
    //  rather than through a Json.NET setting they recognize.
    //
    //  Newtonsoft does NOT check that the target type is a "POD"/DTO. Any
    //  loadable type with a usable constructor and writable members will be
    //  instantiated and populated -- and ANY code those members or the
    //  constructor run will execute during deserialization.
    // =====================================================================
    public static class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("usage: UnsafeDeserialization <sample.json>");
                return 2;
            }

            string path = args[0];
            if (!File.Exists(path))
            {
                Console.Error.WriteLine("file not found: " + path);
                return 2;
            }

            string json = File.ReadAllText(path);
            Console.WriteLine("=== input file: " + Path.GetFileName(path) + " ===");
            Console.WriteLine(json);
            Console.WriteLine("------------------------------------------------------------");

            JObject root = JObject.Parse(json);

            // The type name comes straight from the (attacker-controllable) data.
            string typeName = (string)root["__type"];
            JToken payload = root["payload"] ?? root;

            if (string.IsNullOrEmpty(typeName))
            {
                Console.Error.WriteLine("no __type specified in document");
                return 2;
            }

            Console.WriteLine("requested __type : " + typeName);

            // No allow-list, no POD check -- whatever the data names, we load.
            Type targetType = Type.GetType(typeName, throwOnError: false);
            if (targetType == null)
            {
                Console.Error.WriteLine("could not resolve type: " + typeName
                    + "  (type must already be loadable in this process)");
                return 1;
            }

            Console.WriteLine("resolved type    : " + targetType.AssemblyQualifiedName);
            Console.WriteLine("is value/POD-ish : " + DescribeType(targetType));
            Console.WriteLine("------------------------------------------------------------");

            try
            {
                // *** The call under investigation. ***
                object result = payload.ToObject(targetType);

                Console.WriteLine("ToObject() returned an instance of: "
                    + (result == null ? "<null>" : result.GetType().FullName));
                Console.WriteLine("ToString() => " + (result == null ? "<null>" : result.ToString()));
            }
            catch (Exception ex)
            {
                // Surface the real exception type -- useful when a gadget's
                // setter throws after already having had its side effect.
                Console.Error.WriteLine("ToObject threw: " + ex.GetType().FullName
                    + ": " + ex.Message);
                return 1;
            }

            return 0;
        }

        private static string DescribeType(Type t)
        {
            bool hasParameterlessCtor = t.GetConstructor(Type.EmptyTypes) != null;
            return string.Format(
                "isValueType={0}, isClass={1}, parameterlessCtor={2}, assembly={3}",
                t.IsValueType, t.IsClass, hasParameterlessCtor, t.Assembly.GetName().Name);
        }
    }
}
