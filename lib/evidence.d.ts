import { basename } from 'node:path';
export declare const EVIDENCE_SCHEMA = "dsh-release-evidence/1";
/** The kinds of evidence a release pack can carry, and whether a release may omit it. */
export declare const EVIDENCE_KINDS: {
    readonly 'lifecycle-test': {
        readonly required: true;
        readonly tool: "dsh-testkit";
        readonly describes: "real-host install → register → exercise → uninstall";
    };
    readonly 'regression-eval': {
        readonly required: false;
        readonly tool: "dsh-eval-harness";
        readonly describes: "YAML regression cases against a baseline";
    };
    readonly compatibility: {
        readonly required: false;
        readonly tool: "dsh-plugin-compat-check";
        readonly describes: "peer versions and installability";
    };
    readonly 'quality-budget': {
        readonly required: false;
        readonly tool: "dsh-cordis-plugin-kit";
        readonly describes: "size, dependency and quality budgets";
    };
    readonly 'security-audit': {
        readonly required: false;
        readonly tool: "(various)";
        readonly describes: "static or runtime security findings";
    };
    readonly 'packed-artifact': {
        readonly required: true;
        readonly tool: "npm pack";
        readonly describes: "the exact tarball a consumer would install";
    };
    readonly 'build-output': {
        readonly required: false;
        readonly tool: "(various)";
        readonly describes: "compiler or bundler output";
    };
};
export type EvidenceKind = keyof typeof EVIDENCE_KINDS;
/** One artifact inside the pack, digested and attributed. */
export interface EvidenceEntry {
    kind: EvidenceKind;
    /** Path relative to the repository root, so the pack is portable. */
    path: string;
    /** sha256 of the file's bytes. */
    sha256: string;
    bytes: number;
    /** Which tool produced it, when the path or content reveals it. */
    producedBy?: string;
    /** Pass/fail when the artifact states one. */
    status?: 'passed' | 'failed' | 'error' | 'unknown';
    /** A one-line summary extracted from the artifact, when one can be read. */
    summary?: string;
}
/** The plugin build the pack is about. */
export interface EvidenceSubject {
    name: string;
    version: string;
    /** Git commit the working tree was at, when the repo is a git checkout. */
    commit?: string;
    /** sha256 of the packed tarball, when one was found or produced. */
    tarballSha256?: string;
    tarballBytes?: number;
}
export interface ReleaseEvidencePack {
    schema: typeof EVIDENCE_SCHEMA;
    subject: EvidenceSubject;
    entries: EvidenceEntry[];
    /** Merkle root over the entries' leaf hashes, in entry order. */
    evidenceRoot: string;
    createdAt: number;
    /** After this time the pack should be treated as stale. */
    expiresAt: number;
    /** Environment facts that make the results reproducible. */
    environment: {
        node: string;
        platform: string;
        arch: string;
        dshVersions?: string[];
    };
    signature?: string;
    signerPublicKey?: string;
}
/** Merkle root over the entries. A single swapped report changes it. */
export declare function evidenceRoot(entries: EvidenceEntry[]): string;
/** Read a pass/fail verdict out of whatever shape the producing tool used. */
export declare function extractStatus(text: string): {
    status?: EvidenceEntry['status'];
    summary?: string;
};
export interface CollectOptions {
    /** Repository root to scan. */
    root: string;
    /** Extra glob-ish suffixes to treat as evidence, e.g. ['evidence/*.json']. */
    include?: string[];
    /** Produce a tarball with `npm pack` when none is present. */
    pack?: boolean;
    /** Ignore artifacts older than this (ms); defaults to 14 days. */
    maxAgeMs?: number;
    /** Verdict a lifecycle report must carry for the pack to be complete. */
    now?: number;
}
/** Collect evidence artifacts from a repository. */
export declare function collect(options: CollectOptions): {
    entries: EvidenceEntry[];
    scanned: number;
    skipped: string[];
};
/** Read the subject (plugin identity) from package.json and git. */
export declare function readSubject(root: string, tarballPath?: string): EvidenceSubject;
/** Sign a pack with an Ed25519 private key (PEM). */
export declare function signPack(pack: ReleaseEvidencePack, privateKeyPem: string): ReleaseEvidencePack;
export interface PackVerification {
    /** True only when every check passed *and* the pack is complete. */
    ok: boolean;
    /** False when required evidence kinds are absent. */
    complete: boolean;
    signatureValid: boolean;
    digestsValid: boolean;
    rootValid: boolean;
    /** True when the pack is past its expiry. */
    stale: boolean;
    missingKinds: EvidenceKind[];
    failedKinds: EvidenceKind[];
    issues: string[];
    entries: {
        path: string;
        kind: EvidenceKind;
        matches: boolean;
    }[];
}
/**
 * Verify a pack against the files it points at.
 *
 * `root` is optional: without it, digests and the signature are still checked, but the
 * artifacts' contents are not re-read.
 */
export declare function verifyPack(pack: ReleaseEvidencePack, root?: string, now?: number): PackVerification;
/** Render the human-readable half of a pack. */
export declare function renderEvidenceMarkdown(pack: ReleaseEvidencePack, verification?: PackVerification): string;
/** Write a pack plus its rendered report. */
export declare function writePack(targetDirectory: string, pack: ReleaseEvidencePack, verification?: PackVerification): string[];
/** Convenience: read a pack from disk. */
export declare function readPack(path: string): ReleaseEvidencePack;
export { basename };
