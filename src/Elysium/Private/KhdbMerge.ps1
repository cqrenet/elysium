# Streaming KHDB merge and validation. The per-line PowerShell loop this replaces ran roughly a few
# thousand lines a second on Windows PowerShell 5.1 - hours for a full KHDB. Compiled code with the
# same rules does it in minutes: 32-hex lines, optional ":count" suffix (dropped), uppercase output,
# global sort order across shards, duplicates removed.

if (-not ('Elysium.KhdbMerger' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;

namespace Elysium
{
    public sealed class KhdbMerger : IDisposable
    {
        private readonly StreamWriter writer;
        private string previous;

        public long Written { get; private set; }
        public long Duplicates { get; private set; }

        public KhdbMerger(string targetPath)
        {
            writer = new StreamWriter(targetPath, false, new UTF8Encoding(false), 1 << 20);
        }

        // Appends one shard. Each line must be a hash, optionally followed by ":<digits>". Throws
        // InvalidDataException on bad content, or when the output would stop being sorted.
        public void AddShard(string path, string name)
        {
            using (var reader = new StreamReader(path, Encoding.UTF8, true, 1 << 20))
            {
                string line;
                long lineNumber = 0;
                while ((line = reader.ReadLine()) != null)
                {
                    lineNumber++;
                    string hash = KhdbText.Normalize(line, name, lineNumber);
                    if (hash == null) continue;
                    if (previous != null)
                    {
                        int order = string.CompareOrdinal(hash, previous);
                        if (order < 0)
                            throw new InvalidDataException(string.Format(
                                "Shard merge would produce an unsorted KHDB file at '{0}' line {1}.", name, lineNumber));
                        if (order == 0) { Duplicates++; continue; }
                    }
                    writer.Write(hash);
                    writer.Write(Environment.NewLine);
                    previous = hash;
                    Written++;
                }
            }
        }

        public void Dispose()
        {
            writer.Dispose();
        }
    }

    public static class KhdbText
    {
        private static bool IsHex(char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }

        // Returns the uppercase hash of a "HASH" or "HASH:count" line, or null for a blank line.
        public static string Normalize(string line, string source, long lineNumber)
        {
            string trimmed = line.Trim();
            if (trimmed.Length == 0) return null;

            int colon = trimmed.IndexOf(':');
            string hash = colon < 0 ? trimmed : trimmed.Substring(0, colon);
            bool valid = hash.Length == 32;
            for (int i = 0; valid && i < hash.Length; i++) valid = IsHex(hash[i]);
            if (valid && colon >= 0)
            {
                valid = colon + 1 < trimmed.Length;
                for (int i = colon + 1; valid && i < trimmed.Length; i++) valid = trimmed[i] >= '0' && trimmed[i] <= '9';
            }
            if (!valid)
                throw new InvalidDataException(string.Format(
                    "Invalid KHDB content in '{0}' at line {1}: '{2}'.", source, lineNumber, trimmed));

            return hash.ToUpperInvariant();
        }

        // Checks a finished KHDB file (one bare hash per line) in a single pass. Returns the hash count;
        // the duplicate and out-of-order counts come back through the out parameters.
        public static long Validate(string path, out long duplicates, out long outOfOrder)
        {
            duplicates = 0;
            outOfOrder = 0;
            long count = 0;
            string previous = null;
            using (var reader = new StreamReader(path, Encoding.UTF8, true, 1 << 20))
            {
                string line;
                long lineNumber = 0;
                while ((line = reader.ReadLine()) != null)
                {
                    lineNumber++;
                    string trimmed = line.Trim();
                    if (trimmed.Length == 0) continue;
                    if (trimmed.Length != 32)
                        throw new InvalidDataException(string.Format(
                            "Validation failed: unexpected format at line {0} ('{1}').", lineNumber, trimmed));
                    for (int i = 0; i < 32; i++)
                        if (!IsHex(trimmed[i]))
                            throw new InvalidDataException(string.Format(
                                "Validation failed: unexpected format at line {0} ('{1}').", lineNumber, trimmed));

                    string hash = trimmed.ToUpperInvariant();
                    if (previous != null)
                    {
                        int order = string.CompareOrdinal(hash, previous);
                        if (order < 0) outOfOrder++;
                        else if (order == 0) duplicates++;
                    }
                    previous = hash;
                    count++;
                }
            }
            return count;
        }
    }
}
'@
}
