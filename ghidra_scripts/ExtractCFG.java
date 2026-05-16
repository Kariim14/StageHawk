/*
 * ExtractCFG.java
 * =================
 * Ghidra headless script for the Malware Analysis Orchestrator.
 *
 * Purpose:
 * - Walk all functions.
 * - Extract suspicious API references.
 * - Extract strings.
 * - Extract imported DLL names.
 * - Extract memory sections.
 * - Write everything to /tmp/ghidra_out.json.
 *
 * Output file:
 *   /tmp/ghidra_out.json
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ExtractCFG extends GhidraScript {

    private static final String OUTPUT_PATH = "/tmp/ghidra_out.json";

    private static final String[] SUSPICIOUS_APIS = {
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "CreateThread",
        "CreateProcessA",
        "CreateProcessW",
        "ResumeThread",
        "SuspendThread",
        "OpenProcess",
        "NtUnmapViewOfSection",
        "RtlDecompressBuffer",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",

        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "GetTickCount",
        "QueryPerformanceCounter",

        "CreateMutexA",
        "CreateMutexW",
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegDeleteValueA",
        "RegDeleteValueW",

        "socket",
        "connect",
        "send",
        "recv",
        "WSAStartup",
        "inet_pton",

        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
        "GetComputerNameA",
        "GetComputerNameW",
        "GetUserNameA",
        "GetUserNameW",

        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "UnhookWindowsHookEx",
        "GetDC",
        "BitBlt"
    };

    private static class ApiHit {
        String api;
        String fromAddress;
        String toAddress;
        String containingFunction;

        ApiHit(String api, String fromAddress, String toAddress, String containingFunction) {
            this.api = api;
            this.fromAddress = fromAddress;
            this.toAddress = toAddress;
            this.containingFunction = containingFunction;
        }
    }

    private static class FunctionInfo {
        String name;
        String entry;

        FunctionInfo(String name, String entry) {
            this.name = name;
            this.entry = entry;
        }
    }

    private static class SectionInfo {
        String name;
        String start;
        String end;
        long size;
        boolean read;
        boolean write;
        boolean execute;
        boolean initialized;

        SectionInfo(String name, String start, String end, long size,
                    boolean read, boolean write, boolean execute, boolean initialized) {
            this.name = name;
            this.start = start;
            this.end = end;
            this.size = size;
            this.read = read;
            this.write = write;
            this.execute = execute;
            this.initialized = initialized;
        }
    }

    @Override
    public void run() throws Exception {
        println("[ExtractCFG] Starting analysis for: " + currentProgram.getName());

        Listing listing = currentProgram.getListing();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        ReferenceManager refManager = currentProgram.getReferenceManager();

        List<ApiHit> suspiciousHits = new ArrayList<>();
        List<FunctionInfo> functions = new ArrayList<>();
        List<SectionInfo> sections = new ArrayList<>();

        Set<String> allStrings = new LinkedHashSet<>();
        Set<String> importedDlls = new LinkedHashSet<>();
        Set<String> importedSymbols = new LinkedHashSet<>();

        int functionCount = collectFunctions(functions);
        collectStrings(listing, allStrings);
        collectMemorySections(sections);
        collectExternalSymbols(symbolTable, importedDlls, importedSymbols, refManager, suspiciousHits);
        collectFunctionNameMatches(functions, suspiciousHits);

        writeJson(functionCount, functions, allStrings, importedDlls, importedSymbols, sections, suspiciousHits);

        println("[ExtractCFG] Done.");
        println("[ExtractCFG] Output written to: " + OUTPUT_PATH);
        println("[ExtractCFG] Function count: " + functionCount);
        println("[ExtractCFG] Strings found: " + allStrings.size());
        println("[ExtractCFG] Imported symbols found: " + importedSymbols.size());
        println("[ExtractCFG] Suspicious hits found: " + suspiciousHits.size());
    }

    private int collectFunctions(List<FunctionInfo> functions) {
        int count = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);

        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            count++;
            functions.add(new FunctionInfo(
                safe(f.getName()),
                safe(f.getEntryPoint().toString())
            ));
        }

        return count;
    }

    private void collectStrings(Listing listing, Set<String> allStrings) {
        DataIterator dataIterator = listing.getDefinedData(true);

        while (dataIterator.hasNext() && !monitor.isCancelled()) {
            Data data = dataIterator.next();
            Object value = data.getValue();

            if (value instanceof String) {
                String s = ((String) value).trim();

                if (s.length() >= 4 && s.length() <= 300) {
                    allStrings.add(s);
                }
            }
        }
    }

    private void collectMemorySections(List<SectionInfo> sections) {
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        for (MemoryBlock block : blocks) {
            sections.add(new SectionInfo(
                safe(block.getName()),
                safe(block.getStart().toString()),
                safe(block.getEnd().toString()),
                block.getSize(),
                block.isRead(),
                block.isWrite(),
                block.isExecute(),
                block.isInitialized()
            ));
        }
    }

    private void collectExternalSymbols(SymbolTable symbolTable,
                                        Set<String> importedDlls,
                                        Set<String> importedSymbols,
                                        ReferenceManager refManager,
                                        List<ApiHit> suspiciousHits) {
        SymbolIterator symbols = symbolTable.getAllSymbols(true);

        while (symbols.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = symbols.next();

            if (!symbol.isExternal()) {
                continue;
            }

            String symbolName = safe(symbol.getName());
            String fullName = safe(symbol.getName(true));
            importedSymbols.add(fullName);

            String namespace = "";
            if (symbol.getParentNamespace() != null) {
                namespace = safe(symbol.getParentNamespace().getName(true));
                String upper = namespace.toUpperCase();

                if (upper.endsWith(".DLL") || upper.contains(".DLL")) {
                    importedDlls.add(namespace);
                }
            }

            String matchedApi = matchSuspiciousApi(symbolName);
            if (matchedApi == null) {
                matchedApi = matchSuspiciousApi(fullName);
            }

            if (matchedApi != null) {
                Address target = symbol.getAddress();
                ReferenceIterator refs = refManager.getReferencesTo(target);

                boolean foundReference = false;

                while (refs.hasNext() && !monitor.isCancelled()) {
                    foundReference = true;
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();

                    Function containing = currentProgram.getFunctionManager().getFunctionContaining(from);
                    String containingName = containing != null ? containing.getName() : "UNKNOWN";

                    suspiciousHits.add(new ApiHit(
                        matchedApi,
                        safe(from.toString()),
                        safe(target.toString()),
                        safe(containingName)
                    ));
                }

                if (!foundReference) {
                    suspiciousHits.add(new ApiHit(
                        matchedApi,
                        "NO_REFERENCE_FOUND",
                        safe(target.toString()),
                        "UNKNOWN"
                    ));
                }
            }
        }
    }

    private void collectFunctionNameMatches(List<FunctionInfo> functions, List<ApiHit> suspiciousHits) {
        for (FunctionInfo f : functions) {
            String matchedApi = matchSuspiciousApi(f.name);

            if (matchedApi != null) {
                suspiciousHits.add(new ApiHit(
                    matchedApi,
                    f.entry,
                    f.entry,
                    f.name
                ));
            }
        }
    }

    private String matchSuspiciousApi(String text) {
        if (text == null) {
            return null;
        }

        String lower = text.toLowerCase();

        for (String api : SUSPICIOUS_APIS) {
            if (lower.contains(api.toLowerCase())) {
                return api;
            }
        }

        return null;
    }

    private void writeJson(int functionCount,
                           List<FunctionInfo> functions,
                           Set<String> allStrings,
                           Set<String> importedDlls,
                           Set<String> importedSymbols,
                           List<SectionInfo> sections,
                           List<ApiHit> suspiciousHits) throws Exception {

        PrintWriter out = new PrintWriter(new FileWriter(OUTPUT_PATH));

        out.println("{");
        out.println("  \"program_name\": \"" + json(currentProgram.getName()) + "\",");
        out.println("  \"image_base\": \"" + json(currentProgram.getImageBase().toString()) + "\",");
        out.println("  \"function_count\": " + functionCount + ",");

        out.println("  \"imported_dlls\": [");
        writeStringArray(out, importedDlls, "    ");
        out.println("  ],");

        out.println("  \"imported_symbols\": [");
        writeStringArray(out, importedSymbols, "    ");
        out.println("  ],");

        out.println("  \"all_strings\": [");
        writeStringArray(out, allStrings, "    ");
        out.println("  ],");

        out.println("  \"memory_sections\": [");
        for (int i = 0; i < sections.size(); i++) {
            SectionInfo s = sections.get(i);
            out.println("    {");
            out.println("      \"name\": \"" + json(s.name) + "\",");
            out.println("      \"start\": \"" + json(s.start) + "\",");
            out.println("      \"end\": \"" + json(s.end) + "\",");
            out.println("      \"size\": " + s.size + ",");
            out.println("      \"read\": " + s.read + ",");
            out.println("      \"write\": " + s.write + ",");
            out.println("      \"execute\": " + s.execute + ",");
            out.println("      \"initialized\": " + s.initialized);
            out.print("    }");
            if (i < sections.size() - 1) out.println(",");
            else out.println();
        }
        out.println("  ],");

        out.println("  \"functions\": [");
        for (int i = 0; i < functions.size(); i++) {
            FunctionInfo f = functions.get(i);
            out.println("    {");
            out.println("      \"name\": \"" + json(f.name) + "\",");
            out.println("      \"entry\": \"" + json(f.entry) + "\"");
            out.print("    }");
            if (i < functions.size() - 1) out.println(",");
            else out.println();
        }
        out.println("  ],");

        out.println("  \"suspicious_addresses\": [");
        for (int i = 0; i < suspiciousHits.size(); i++) {
            ApiHit h = suspiciousHits.get(i);
            out.println("    {");
            out.println("      \"api\": \"" + json(h.api) + "\",");
            out.println("      \"from_address\": \"" + json(h.fromAddress) + "\",");
            out.println("      \"to_address\": \"" + json(h.toAddress) + "\",");
            out.println("      \"containing_function\": \"" + json(h.containingFunction) + "\"");
            out.print("    }");
            if (i < suspiciousHits.size() - 1) out.println(",");
            else out.println();
        }
        out.println("  ]");

        out.println("}");
        out.close();
    }

    private void writeStringArray(PrintWriter out, Set<String> values, String indent) {
        int i = 0;
        int size = values.size();

        for (String value : values) {
            out.print(indent + "\"" + json(value) + "\"");
            if (i < size - 1) out.println(",");
            else out.println();
            i++;
        }
    }

    private String safe(String s) {
        return s == null ? "" : s;
    }

    private String json(String s) {
        if (s == null) {
            return "";
        }

        return s
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }
}
