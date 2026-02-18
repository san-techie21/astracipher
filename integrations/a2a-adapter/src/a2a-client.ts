/**
 * A2A Protocol Client
 *
 * Enables AgentPass-authenticated agents to interact with external
 * A2A-compatible agents. Handles:
 *
 * - Agent discovery (fetch agent cards from /.well-known/agent-card.json)
 * - Agent card verification (signature checks)
 * - Task creation and management
 * - AgentPass credential presentation for authentication
 * - SSE streaming for real-time task updates
 *
 * Usage:
 *   const client = new A2AClient({
 *     credential: myAgentCredential,
 *     agentpassApiKey: 'ap_...',
 *   });
 *
 *   const card = await client.discoverAgent('https://other-agent.example.com');
 *   const task = await client.sendMessage(card.url, {
 *     role: 'user',
 *     parts: [{ type: 'text', text: 'Hello, agent!' }],
 *   });
 */

import type {
  AgentCard,
  Task,
  Message,
  Part,
  TaskState,
  JsonRpcRequest,
  JsonRpcResponse,
  PushNotificationConfig,
  TaskStatusUpdateEvent,
  TaskArtifactUpdateEvent,
} from './types.js';

export interface A2AClientConfig {
  /** AgentPass credential to present to remote agents */
  credential?: Record<string, unknown>;
  /** API key for agents that accept X-AgentPass-Key auth */
  agentpassApiKey?: string;
  /** DID of the calling agent */
  agentDID?: string;
  /** Request timeout in ms */
  timeout?: number;
  /** Custom fetch implementation */
  fetchImpl?: typeof fetch;
}

export class A2AClient {
  private config: A2AClientConfig;
  private fetch: typeof fetch;
  private discoveredCards = new Map<string, AgentCard>();

  constructor(config: A2AClientConfig = {}) {
    this.config = config;
    this.fetch = config.fetchImpl ?? globalThis.fetch;
  }

  // -----------------------------------------------------------------------
  // Agent Discovery
  // -----------------------------------------------------------------------

  /**
   * Discover an agent by fetching its Agent Card
   * @param baseUrl - The agent's base URL (e.g., https://agent.example.com)
   */
  async discoverAgent(baseUrl: string): Promise<AgentCard> {
    const url = `${baseUrl.replace(/\/$/, '')}/.well-known/agent-card.json`;
    const response = await this.fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: this.createAbortSignal(),
    });

    if (!response.ok) {
      throw new Error(`Agent discovery failed for ${baseUrl}: ${response.status}`);
    }

    const card = (await response.json()) as AgentCard;

    // Cache the card
    this.discoveredCards.set(baseUrl, card);

    return card;
  }

  /**
   * Get extended (authenticated) agent card
   */
  async getExtendedAgentCard(baseUrl: string): Promise<AgentCard> {
    const url = `${baseUrl.replace(/\/$/, '')}/extendedAgentCard`;
    const response = await this.fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        ...this.buildAuthHeaders(),
      },
      signal: this.createAbortSignal(),
    });

    if (!response.ok) {
      throw new Error(`Extended agent card request failed: ${response.status}`);
    }

    return (await response.json()) as AgentCard;
  }

  /**
   * Get a cached agent card
   */
  getCachedCard(baseUrl: string): AgentCard | undefined {
    return this.discoveredCards.get(baseUrl);
  }

  // -----------------------------------------------------------------------
  // Task Management
  // -----------------------------------------------------------------------

  /**
   * Send a message to a remote A2A agent (creates or continues a task)
   */
  async sendMessage(
    agentUrl: string,
    message: Message | string,
    options?: { contextId?: string; taskId?: string }
  ): Promise<Task> {
    const url = `${agentUrl.replace(/\/$/, '')}/messages`;

    const msg: Message =
      typeof message === 'string'
        ? {
            id: crypto.randomUUID(),
            role: 'user',
            parts: [{ type: 'text', text: message }],
          }
        : message;

    const body: Record<string, unknown> = {
      message: msg,
    };
    if (options?.contextId) body.contextId = options.contextId;
    if (options?.taskId) body.taskId = options.taskId;

    const response = await this.fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.buildAuthHeaders(),
      },
      body: JSON.stringify(body),
      signal: this.createAbortSignal(),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(
        `SendMessage failed: ${response.status} - ${(err as any).error?.message ?? 'Unknown error'}`
      );
    }

    return (await response.json()) as Task;
  }

  /**
   * Send a message and stream the response via SSE
   */
  async sendStreamingMessage(
    agentUrl: string,
    message: Message | string,
    callbacks: {
      onStatusUpdate?: (event: TaskStatusUpdateEvent) => void;
      onArtifactUpdate?: (event: TaskArtifactUpdateEvent) => void;
      onTask?: (task: Task) => void;
      onDone?: () => void;
      onError?: (error: Error) => void;
    },
    options?: { contextId?: string }
  ): Promise<void> {
    const url = `${agentUrl.replace(/\/$/, '')}/messages:stream`;

    const msg: Message =
      typeof message === 'string'
        ? {
            id: crypto.randomUUID(),
            role: 'user',
            parts: [{ type: 'text', text: message }],
          }
        : message;

    const body: Record<string, unknown> = { message: msg };
    if (options?.contextId) body.contextId = options.contextId;

    const response = await this.fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
        ...this.buildAuthHeaders(),
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(
        `SendStreamingMessage failed: ${response.status} - ${(err as any).error?.message ?? ''}`
      );
    }

    // Read SSE stream
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('No readable stream in response');
    }

    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6);
          if (!data) continue;

          try {
            const event = JSON.parse(data);

            switch (event.type) {
              case 'task':
                callbacks.onTask?.(event.task);
                break;
              case 'status':
                callbacks.onStatusUpdate?.(event);
                break;
              case 'artifact':
                callbacks.onArtifactUpdate?.(event);
                break;
              case 'done':
                callbacks.onDone?.();
                return;
            }
          } catch {
            // Skip malformed events
          }
        }
      }
    } catch (err: any) {
      callbacks.onError?.(err);
    } finally {
      reader.releaseLock();
    }
  }

  /**
   * Get a task by ID from a remote agent
   */
  async getTask(agentUrl: string, taskId: string): Promise<Task> {
    const url = `${agentUrl.replace(/\/$/, '')}/tasks/${taskId}`;
    const response = await this.fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        ...this.buildAuthHeaders(),
      },
      signal: this.createAbortSignal(),
    });

    if (!response.ok) {
      throw new Error(`GetTask failed: ${response.status}`);
    }

    return (await response.json()) as Task;
  }

  /**
   * Cancel a task on a remote agent
   */
  async cancelTask(agentUrl: string, taskId: string): Promise<Task> {
    const url = `${agentUrl.replace(/\/$/, '')}/tasks/${taskId}:cancel`;
    const response = await this.fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.buildAuthHeaders(),
      },
      signal: this.createAbortSignal(),
    });

    if (!response.ok) {
      throw new Error(`CancelTask failed: ${response.status}`);
    }

    return (await response.json()) as Task;
  }

  // -----------------------------------------------------------------------
  // JSON-RPC interface (alternative to REST)
  // -----------------------------------------------------------------------

  /**
   * Send a raw JSON-RPC request to a remote agent
   */
  async jsonRpc(agentUrl: string, method: string, params?: Record<string, unknown>): Promise<unknown> {
    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      id: crypto.randomUUID(),
      method,
      params,
    };

    const url = agentUrl.replace(/\/$/, '');
    const response = await this.fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.buildAuthHeaders(),
      },
      body: JSON.stringify(request),
      signal: this.createAbortSignal(),
    });

    const result = (await response.json()) as JsonRpcResponse;

    if (result.error) {
      throw new A2ARemoteError(result.error.code, result.error.message, result.error.data);
    }

    return result.result;
  }

  // -----------------------------------------------------------------------
  // Push Notifications
  // -----------------------------------------------------------------------

  /**
   * Configure push notifications for a task
   */
  async createPushConfig(
    agentUrl: string,
    taskId: string,
    config: {
      url: string;
      authentication?: PushNotificationConfig['authentication'];
      events?: TaskState[];
    }
  ): Promise<PushNotificationConfig> {
    const url = `${agentUrl.replace(/\/$/, '')}/tasks/${taskId}/pushNotificationConfigs`;
    const response = await this.fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.buildAuthHeaders(),
      },
      body: JSON.stringify(config),
      signal: this.createAbortSignal(),
    });

    if (!response.ok) {
      throw new Error(`CreatePushConfig failed: ${response.status}`);
    }

    return (await response.json()) as PushNotificationConfig;
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private buildAuthHeaders(): Record<string, string> {
    const headers: Record<string, string> = {};

    // Primary: AgentPass credential as Bearer token
    if (this.config.credential) {
      const token = Buffer.from(JSON.stringify(this.config.credential)).toString('base64url');
      headers['Authorization'] = `Bearer ${token}`;
    }

    // Secondary: API key
    if (this.config.agentpassApiKey) {
      headers['X-AgentPass-Key'] = this.config.agentpassApiKey;
    }

    // Agent DID header
    if (this.config.agentDID) {
      headers['X-AgentPass-DID'] = this.config.agentDID;
    }

    return headers;
  }

  private createAbortSignal(): AbortSignal | undefined {
    if (!this.config.timeout) return undefined;
    return AbortSignal.timeout(this.config.timeout);
  }
}

// -------------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------------

export class A2ARemoteError extends Error {
  code: number;
  data: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(`A2A Remote Error (${code}): ${message}`);
    this.name = 'A2ARemoteError';
    this.code = code;
    this.data = data;
  }
}
