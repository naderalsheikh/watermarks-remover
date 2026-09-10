import { describe, it, expect } from "vitest";
import {
  ACCEPT_ATTR,
  fileExtension,
  isAcceptedFilename,
  validateUploadFilename,
} from "./uploadValidation";

describe("fileExtension", () => {
  it("lowercases and includes the dot", () => {
    expect(fileExtension("Engagement.DOCX")).toBe(".docx");
    expect(fileExtension("brief.PDF")).toBe(".pdf");
  });
  it("returns empty string when there is no extension", () => {
    expect(fileExtension("README")).toBe("");
    expect(fileExtension(".gitignore")).toBe("");
  });
  it("uses the final path segment", () => {
    expect(fileExtension("some/dir/file.md")).toBe(".md");
    expect(fileExtension("C:\\docs\\file.html")).toBe(".html");
  });
});

describe("isAcceptedFilename", () => {
  it("accepts the legal document core", () => {
    for (const n of ["a.docx", "a.pdf", "a.md", "a.markdown", "a.html", "a.htm", "a.txt"]) {
      expect(isAcceptedFilename(n)).toBe(true);
    }
  });
  it("accepts supported image formats", () => {
    for (const n of ["exhibit.png", "exhibit.jpg", "exhibit.jpeg", "logo.svg"]) {
      expect(isAcceptedFilename(n)).toBe(true);
    }
  });
  it("rejects unsupported types", () => {
    for (const n of ["a.exe", "a.zip", "a.xlsx", "a.doc", "noext"]) {
      expect(isAcceptedFilename(n)).toBe(false);
    }
  });
});

describe("validateUploadFilename", () => {
  it("returns null for accepted files", () => {
    expect(validateUploadFilename("Sale Agreement.docx")).toBeNull();
  });
  it("prompts to choose a file when empty", () => {
    expect(validateUploadFilename("")).toMatch(/choose a file/i);
  });
  it("names the offending extension", () => {
    expect(validateUploadFilename("malware.exe")).toContain('".exe"');
  });
  it("handles no-extension files", () => {
    expect(validateUploadFilename("Makefile")).toMatch(/without an extension/i);
  });
});

describe("ACCEPT_ATTR", () => {
  it("is a comma-joined extension list for the input accept attribute", () => {
    expect(ACCEPT_ATTR).toContain(".docx");
    expect(ACCEPT_ATTR).toContain(".pdf");
    expect(ACCEPT_ATTR.split(",").length).toBeGreaterThan(4);
  });
});
