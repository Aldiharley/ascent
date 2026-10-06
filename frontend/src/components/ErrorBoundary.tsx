import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  failed: boolean;
}

/**
 * Isolates a render failure to one view. The message is a fixed string: the
 * thrown error can carry scanned-target data, so it is never shown.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("view failed to render", error, info.componentStack);
  }

  private reset = () => {
    this.setState({ failed: false });
  };

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <section className="panel glass" role="alert">
        <div className="phead">
          <span className="ptitle">This view failed to render.</span>
        </div>
        <button type="button" onClick={this.reset}>
          Try again
        </button>
      </section>
    );
  }
}
