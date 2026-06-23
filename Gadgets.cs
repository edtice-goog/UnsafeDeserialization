using System;
using System.IO;

namespace UnsafeDeserialization
{
    // ---------------------------------------------------------------------
    //  A genuine POD / DTO -- the kind of type the developer *expected*
    //  ToObject to be used with. Plain auto-properties, no behavior.
    // ---------------------------------------------------------------------
    public class BenignPayload
    {
        public string Name { get; set; }
        public int Age { get; set; }

        public override string ToString()
        {
            return string.Format("BenignPayload {{ Name = {0}, Age = {1} }}", Name, Age);
        }
    }

    // ---------------------------------------------------------------------
    //  A "gadget": NOT a POD. A property setter does real work. When
    //  Newtonsoft populates this object during ToObject(), the setter runs
    //  -- so attacker-controlled JSON drives code execution. To keep this
    //  demo non-destructive, the "real work" is only: print a loud warning
    //  and drop a marker file in TEMP. A malicious gadget would do worse.
    // ---------------------------------------------------------------------
    public class SideEffectGadget
    {
        private string _command;

        public string Command
        {
            get { return _command; }
            set
            {
                _command = value;
                // *** This runs purely because Json.NET set a property. ***
                string marker = Path.Combine(
                    Path.GetTempPath(),
                    "UNSAFE_DESERIALIZATION_PROOF.txt");
                File.WriteAllText(marker,
                    "Code executed during deserialization at property-set time." + Environment.NewLine +
                    "Simulated command from attacker JSON: " + value + Environment.NewLine +
                    "Timestamp(UTC): " + DateTime.UtcNow.ToString("o") + Environment.NewLine);

                Console.WriteLine("    [!] SideEffectGadget.Command setter fired during deserialization");
                Console.WriteLine("    [!] would-be command: " + value);
                Console.WriteLine("    [!] wrote proof marker: " + marker);
            }
        }

        public override string ToString()
        {
            return "SideEffectGadget { Command = " + _command + " }";
        }
    }

    // ---------------------------------------------------------------------
    //  Another gadget whose side effect is in the constructor itself, so it
    //  fires even before any property is set -- as long as the type can be
    //  constructed by the deserializer.
    // ---------------------------------------------------------------------
    public class ConstructorGadget
    {
        public string Note { get; set; }

        public ConstructorGadget()
        {
            Console.WriteLine("    [!] ConstructorGadget ctor fired during deserialization");
        }

        public override string ToString()
        {
            return "ConstructorGadget { Note = " + Note + " }";
        }
    }
}
