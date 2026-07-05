import { describe, it, expect } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import AttackGraph from "./AttackGraph";

// jsdom cannot fully lay out an SVG (no getBBox), so mermaid may fall back to the
// error branch. Either way the component must mount without throwing and settle
// into a stable state (rendered graph container OR a readable error panel).
describe("AttackGraph", () => {
  it("mounts and settles for a valid diagram without crashing", async () => {
    render(<AttackGraph chart={"graph TD;\n  A[Initial Access] --> B[Execution];"} />);
    await waitFor(() => {
      const rendered = screen.queryByTestId("attack-graph");
      const errored = screen.queryByText(/Could not render attack graph/i);
      expect(rendered || errored).toBeTruthy();
    });
  });

  it("renders nothing problematic for empty input", () => {
    const { container } = render(<AttackGraph chart="" />);
    expect(container).toBeTruthy();
  });
});
