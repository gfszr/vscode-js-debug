/// <reference types="node" />
/** Runs a traditional pre-Chrome 104 hash of the bytes. */
export declare const hash: (input: Buffer) => string;
/** Runs a traditional pre-Chrome 104 hash of the bytes. */
export declare const shaHash: (input: Buffer) => string;
/** Runs a traditional pre-Chrome 104 hash of the file. */
export declare const hashFile: (file: string, bufferSize?: number) => Promise<string>;
/** Runs a modern SHA hash of the file */
export declare const shaHashFile: (file: string, bufferSize?: number) => Promise<string>;
