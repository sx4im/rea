import * as t from "@babel/types";

/** Declaration syntax that establishes no runtime value, regardless of export form. */
export const isErasedJavaScriptDeclaration = (node: t.Node): boolean =>
  t.isTSInterfaceDeclaration(node) ||
  t.isTSTypeAliasDeclaration(node) ||
  t.isTSDeclareFunction(node) ||
  ((t.isVariableDeclaration(node) ||
    t.isClassDeclaration(node) ||
    t.isTSEnumDeclaration(node) ||
    t.isTSModuleDeclaration(node)) &&
    node.declare === true);

/** Namespace/enum lowering introduces runtime scopes absent from this source index. */
export const isUnmodeledJavaScriptRuntimeScope = (node: t.Node): boolean =>
  t.isTSModuleDeclaration(node) || t.isTSEnumDeclaration(node);

/** Whether TypeScript explicitly erases this entire import declaration. */
export const isTypeOnlyImportDeclaration = (
  node: t.ImportDeclaration,
): boolean => node.importKind === "type" || node.importKind === "typeof";

/** Whether TypeScript explicitly erases this entire export declaration. */
export const isTypeOnlyExportDeclaration = (
  node: t.ExportNamedDeclaration | t.ExportAllDeclaration,
): boolean =>
  node.exportKind === "type" ||
  (t.isExportNamedDeclaration(node) &&
    node.declaration !== null &&
    (t.isTSInterfaceDeclaration(node.declaration) ||
      t.isTSTypeAliasDeclaration(node.declaration) ||
      t.isTSDeclareFunction(node.declaration)));

/**
 * Runtime external-module target for a value import-equals declaration;
 * `import type X = require("m")` is erased and declares no dependency.
 */
export const semanticImportEqualsSpecifier = (
  node: t.TSImportEqualsDeclaration,
): string | null =>
  node.importKind !== "type" &&
  t.isTSExternalModuleReference(node.moduleReference) &&
  t.isStringLiteral(node.moduleReference.expression)
    ? node.moduleReference.expression.value
    : null;

/** Whether this import binding is explicitly type-only. */
export const isTypeOnlyImportSpecifier = (node: t.ImportSpecifier): boolean =>
  node.importKind === "type" || node.importKind === "typeof";

/** Whether this exported binding is explicitly type-only. */
export const isTypeOnlyExportSpecifier = (node: t.ExportSpecifier): boolean =>
  node.exportKind === "type";

/** A regular import whose bindings are all erased but may retain side effects. */
export const hasOnlyInlineTypeImportSpecifiers = (
  node: t.ImportDeclaration,
): boolean =>
  !isTypeOnlyImportDeclaration(node) &&
  node.specifiers.length > 0 &&
  node.specifiers.every(
    (specifier) =>
      t.isImportSpecifier(specifier) && isTypeOnlyImportSpecifier(specifier),
  );

/** A regular re-export whose bindings are all erased but may retain side effects. */
export const hasOnlyInlineTypeExportSpecifiers = (
  node: t.ExportNamedDeclaration,
): boolean =>
  !isTypeOnlyExportDeclaration(node) &&
  node.source != null &&
  node.specifiers.length > 0 &&
  node.specifiers.every(
    (specifier) =>
      t.isExportSpecifier(specifier) && isTypeOnlyExportSpecifier(specifier),
  );

/** Whether compiler options leave an inline type-only declaration's side effect unknown. */
export const hasUncertainTypeOnlyModuleSideEffect = (
  program: t.Program,
): boolean =>
  program.body.some(
    (node) =>
      (t.isImportDeclaration(node) &&
        hasOnlyInlineTypeImportSpecifiers(node)) ||
      (t.isExportNamedDeclaration(node) &&
        hasOnlyInlineTypeExportSpecifiers(node)),
  );
