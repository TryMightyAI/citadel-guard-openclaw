/**
 * Type declarations for openclaw/plugin-sdk
 *
 * This file provides type definitions for the OpenClaw plugin SDK.
 * These types allow the plugin to properly type-check against the host framework.
 */

declare module "openclaw/plugin-sdk" {
  export interface Logger {
    info(msg: string): void;
    warn?(msg: string): void;
    error?(msg: string): void;
    debug?(msg: string): void;
  }

  export interface PluginConfig {
    plugins?: {
      entries?: {
        [pluginId: string]: {
          config?: unknown;
        };
      };
    };
  }

  export interface HookEvent {
    content?: string;
    metadata?: {
      conversationId?: string;
      channelId?: string;
      accountId?: string;
      [key: string]: unknown;
    };
    toolName?: string;
    params?: unknown;
    result?: unknown;
    prompt?: string;
    message?: unknown;
    [key: string]: unknown;
  }

  export interface HookContext {
    sessionKey?: string;
    logger?: Logger;
    [key: string]: unknown;
  }

  export interface HookResult {
    block?: boolean;
    blockReason?: string;
    blockResponse?: string;
    content?: string;
    message?: string;
    prependContext?: string;
    [key: string]: unknown;
  }

  export type HookHandler = (
    event: HookEvent,
    context?: HookContext
  ) => void | HookResult | Promise<void | HookResult | undefined>;

  export interface ToolDefinition {
    name: string;
    description: string;
    parameters: unknown;
    execute(id: string, params: unknown): Promise<{
      content: Array<{ type: string; text: string }>;
    }>;
  }

  export interface ToolOptions {
    optional?: boolean;
  }

  export interface ServiceDefinition {
    id: string;
    start(ctx: OpenClawPluginServiceContext): void | Promise<void>;
    stop(ctx: OpenClawPluginServiceContext): void | Promise<void>;
  }

  export interface OpenClawPluginServiceContext {
    stateDir: string;
    config?: PluginConfig;
    logger: Logger & {
      error(msg: string): void;
    };
  }

  export interface OpenClawPluginApi {
    pluginConfig?: unknown;
    config?: PluginConfig;
    logger: Logger;

    registerTool(tool: ToolDefinition, options?: ToolOptions): void;
    registerService(service: ServiceDefinition): void;

    on(event: "message_received", handler: HookHandler): void;
    on(event: "message_sending", handler: HookHandler): void;
    on(event: "before_tool_call", handler: HookHandler): void;
    on(event: "after_tool_call", handler: HookHandler): void;
    on(event: "tool_result_persist", handler: (event: HookEvent) => void | HookResult): void;
    on(event: "before_agent_start", handler: HookHandler): void;
    on(event: string, handler: HookHandler): void;
  }
}
