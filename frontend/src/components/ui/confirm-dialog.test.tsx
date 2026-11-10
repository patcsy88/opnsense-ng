import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "./confirm-dialog";

describe("ConfirmDialog", () => {
  it("confirms and cancels", () => {
    const onConfirm = vi.fn();
    const onOpenChange = vi.fn();
    render(
      <ConfirmDialog open onOpenChange={onOpenChange} title="Sure?" description="desc" onConfirm={onConfirm} />,
    );
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("requires typed text when requested", () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog open onOpenChange={() => {}} title="t" description="d" requireText="edge-1" onConfirm={onConfirm} />,
    );
    const confirm = screen.getByRole("button", { name: "Confirm" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/type/i), { target: { value: "edge-1" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    expect(onConfirm).toHaveBeenCalled();
  });

  it("disables actions while pending and shows errors", () => {
    render(
      <ConfirmDialog open onOpenChange={() => {}} title="t" description="d" pending error="boom" onConfirm={() => {}} />,
    );
    expect(screen.getByRole("button", { name: /working/i })).toBeDisabled();
    expect(screen.getByText("boom")).toBeInTheDocument();
  });
});
