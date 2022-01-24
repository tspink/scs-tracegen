#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>

using std::cerr;
using std::endl;
using std::string;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "trace output file");

KNOB<BOOL> KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
                     "count instructions, basic blocks and threads in the application");

INT32 Usage()
{
    cerr << "This tool generates a trace file for use with the scs cache simulator." << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

FILE *trace_output;

VOID Fetch(ADDRINT addr, UINT32 size)
{
    unsigned long int tag = addr;

    tag &= ~(0xffffull << 48);

    tag |= 1ull << 60;

    tag |= ((unsigned long)size & 0xff) << 48;

    fwrite(&tag, sizeof(tag), 1, trace_output);
}

VOID Load(ADDRINT addr, UINT32 size)
{
    unsigned long int tag = addr;

    tag &= ~(0xffffull << 48);
    tag |= 2ull << 60;
    tag |= ((unsigned long)size & 0xff) << 48;

    fwrite(&tag, sizeof(tag), 1, trace_output);
}

VOID Store(ADDRINT addr, UINT32 size)
{
    unsigned long int tag = addr;

    tag &= ~(0xffffull << 48);
    tag |= 3ull << 60;
    tag |= ((unsigned long)size & 0xff) << 48;

    fwrite(&tag, sizeof(tag), 1, trace_output);
}

VOID Instruction(INS ins, void *v)
{
    const ADDRINT iaddr = INS_Address(ins);

    // Register Fetch
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Fetch, IARG_ADDRINT, iaddr, IARG_UINT32, INS_Size(ins), IARG_END);

    // Register Memory
    if (!INS_IsStandardMemop(ins))
    {
        return;
    }

    if (INS_MemoryOperandCount(ins) == 0)
    {
        return;
    }

    UINT32 readOperandCount = 0, writeOperandCount = 0;

    for (UINT32 opIdx = 0; opIdx < INS_MemoryOperandCount(ins); opIdx++)
    {
        if (INS_MemoryOperandIsRead(ins, opIdx))
        {
            readOperandCount++;
        }

        if (INS_MemoryOperandIsWritten(ins, opIdx))
        {
            writeOperandCount++;
        }
    }

    if (readOperandCount > 0)
    {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Load, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }

    if (writeOperandCount > 0)
    {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Store, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    fclose(trace_output);
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    string fileName = KnobOutputFile.Value();

    if (fileName.empty())
    {
        return Usage();
    }

    trace_output = fopen(fileName.c_str(), "wb");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    __builtin_unreachable();
}
