import { ArtifactResourceScope } from "../../src/artifacts/ArtifactResourceScope.js";
import { AnalysisCleanupLease } from "../../src/artifacts/AnalysisCleanupLease.js";
import type { FileCloseResourceOwner } from "../../src/application/AnalysisProvider.js";

/** Test-scoped real inspection leases; every retained owner is closed by the fixture. */
export const createInspectionResources = () => {
  const scope = new ArtifactResourceScope();
  const owner: FileCloseResourceOwner = {
    retain: (resourceOwner, resource) =>
      scope.retain({
        kind: "lease",
        resource,
        lease: new AnalysisCleanupLease(
          () => resourceOwner.close(),
          [resource],
        ),
      }),
    run: (operation) => scope.run(operation),
  };
  return { owner, close: () => scope.close() };
};
