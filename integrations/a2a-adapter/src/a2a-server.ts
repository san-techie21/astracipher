/**
 * A2A Protocol Server
 *
 * Full implementation of the Google A2A protocol HTTP endpoints:
 *
 *   Discovery:
 *     GET  /.well-known/agent-card.json    — Public Agent Card
 *     GET  /extendedAgentCard              — Authenticated Agent Card
 *
 *   Task Management (JSON-RPC over HTTP):
 *     POST /messages                       — Send message / create task
 *     POST /messages:stream                — Send message with SSE response
 *     GET  /tasks/:id                      — Get task status
 *     GET  /tasks                          — List tasks
 *     POST /tasks/:id:cancel               — Cancel task
 *     GET  /tasks/:id:subscribe            — SSE subscribe to task
 *
 *   Push Notifications:
 *     POST   /tasks/:taskId/pushNotificationConfigs
 *     GET    /tasks/:taskId/pushNotificationConfigs/:id
 *     GET    /tasks/:taskId/pushNotificationConfigs
 *     DELETE /tasks/:taskId/pushNotificationConfigs/:id
 *
 *   Health:
 *     GET  /health                         — Health check
 *
 * All endpoints support AgentPass authentication via the auth middleware.
 */

import express, { type Request as ExpressRequest, type Response as ExpressResponse } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { v4 as uuidv4 } from 'uuid';
import { TaskManager, TaskNotFoundError, TaskNotCancelableError } from './task-manager.js';
import { buildAgentCard, type AgentCardOptions } from './agent-card.js';
import { createAuthMiddleware, type AuthenticatedRequest, type AuthConfig } from './auth.js';
import type {
  AgentCard,
  AgentSkill,
  A2AAdapterConfig,
  Task,
  Message,
  Part,
  JsonRpcRequest,
  JsonRpcResponse,
  TaskHandler,
  TaskState,
} from './types.js';

export interface A2AServerOptions extends A2AAdapterConfig {
  /** Agent card configuration */
  agentCard: AgentCardOptions;
  /** CORS origin (default: reject cross-origin). PUB-MED-4 FIX */
  corsOrigin?: string;
}

export class A2AServer {
  private app: express.Application;
  private taskManager: TaskManager;
  private agentCard: AgentCard;
  private config: A2AServerOptions;

  constructor(options: A2AServerOptions) {
    this.config = options;
    this.app = express();
    this.agentCard = buildAgentCard(options.agentCard);

    // Default task handler echoes a "no handler configured" message
    const handler: TaskHandler = options.taskHandler ?? defaultTaskHandler;
    this.taskManager = new TaskManager(handler);

    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Get the Express app (for custom middleware or testing)
   */
  getApp(): express.Application {
    return this.app;
  }

  /**
   * Start the A2A server
   */
  async start(): Promise<void> {
    const port = this.config.port ?? 3457;
    // PUB-LOW-10 FIX: Default to loopback instead of all interfaces
    const host = this.config.host ?? '127.0.0.1';

    return new Promise((resolve) => {
      this.app.listen(port, host, () => {
        console.log(`A2A adapter running on http://${host}:${port}`);
        console.log(`Agent Card: http://${host}:${port}/.well-known/agent-card.json`);
        console.log(`Agent DID: ${this.agentCard.id}`);
        resolve();
      });
    });
  }

  /**
   * Update the agent card (e.g., after credential renewal)
   */
  updateAgentCard(options: Partial<AgentCardOptions>): void {
    this.agentCard = buildAgentCard({
      ...this.config.agentCard,
      ...options,
    });
  }

  // -----------------------------------------------------------------------
  // Middleware setup
  // -----------------------------------------------------------------------

  private setupMiddleware(): void {
    // PUB-MED-5 FIX: Security headers via helmet
    this.app.use(helmet({
      contentSecurityPolicy: false, // JSON API, not serving HTML
      crossOriginResourcePolicy: { policy: 'cross-origin' },
    }));

    // PUB-HIGH-1 FIX: Rate limiting to prevent task flood / SSE exhaustion
    this.app.use(rateLimit({
      windowMs: 60 * 1000, // 1 minute
      max: 100, // 100 requests per minute per IP
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: { code: -32029, message: 'Too many requests, please try again later' } },
    }));

    // LOW-3 FIX: Reduced body limit from 10mb to 512kb — A2A messages are small
    this.app.use(express.json({ limit: '512kb' }));

    // PUB-MED-4 FIX: CORS defaults to rejecting cross-origin (was '*')
    this.app.use((_req, res, next) => {
      const allowedOrigin = this.config.corsOrigin || process.env.A2A_CORS_ORIGIN || '';
      if (allowedOrigin) {
        res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-AgentPass-Key, X-AgentPass-DID');
      }
      res.setHeader('X-A2A-Version', '0.3');
      if (_req.method === 'OPTIONS') return res.sendStatus(204);
      next();
    });

    // AgentPass authentication
    if (this.config.agentpassUrl) {
      const authConfig: AuthConfig = {
        agentpassUrl: this.config.agentpassUrl,
        apiKey: this.config.apiKey,
        allowUnauthenticated: true, // agent card is public
        publicPaths: ['/.well-known/agent-card.json', '/health'],
      };
      this.app.use(createAuthMiddleware(authConfig));
    }
  }

  // -----------------------------------------------------------------------
  // Route setup
  // -----------------------------------------------------------------------

  private setupRoutes(): void {
    const r = this.app;

    // ----- Discovery -----
    r.get('/.well-known/agent-card.json', this.handleGetAgentCard.bind(this));
    r.get('/extendedAgentCard', this.handleGetExtendedAgentCard.bind(this));

    // ----- Health -----
    r.get('/health', this.handleHealth.bind(this));

    // ----- Messages (Task creation) -----
    r.post('/messages', this.handleSendMessage.bind(this));
    r.post('/messages:stream', this.handleSendStreamingMessage.bind(this));

    // ----- Tasks -----
    r.get('/tasks', this.handleListTasks.bind(this));
    r.get('/tasks/:id', this.handleGetTask.bind(this));
    r.post('/tasks/:id:cancel', this.handleCancelTask.bind(this));
    r.get('/tasks/:id:subscribe', this.handleSubscribeToTask.bind(this));

    // ----- Push Notifications -----
    r.post('/tasks/:taskId/pushNotificationConfigs', this.handleCreatePushConfig.bind(this));
    r.get('/tasks/:taskId/pushNotificationConfigs', this.handleListPushConfigs.bind(this));
    r.get('/tasks/:taskId/pushNotificationConfigs/:id', this.handleGetPushConfig.bind(this));
    r.delete('/tasks/:taskId/pushNotificationConfigs/:id', this.handleDeletePushConfig.bind(this));

    // ----- JSON-RPC endpoint (alternative) -----
    r.post('/', this.handleJsonRpc.bind(this));
  }

  // -----------------------------------------------------------------------
  // Discovery handlers
  // -----------------------------------------------------------------------

  private handleGetAgentCard(_req: ExpressRequest, res: express.Response): void {
    res.json(this.agentCard);
  }

  private handleGetExtendedAgentCard(req: AuthenticatedRequest, res: express.Response): void {
    if (!req.agentpass?.verified) {
      res.status(401).json({
        error: { code: -32010, message: 'Authentication required for extended agent card' },
      });
      return;
    }

    // Extended card includes additional metadata
    const extended = {
      ...this.agentCard,
      'x-agentpass-extended': true,
      'x-agentpass-capabilities-detail': this.config.agentCard.skills.map((s) => ({
        ...s,
        requiresTrustLevel: 1,
      })),
      'x-agentpass-network': this.config.network ?? 'testnet',
    };

    res.json(extended);
  }

  // -----------------------------------------------------------------------
  // Health
  // -----------------------------------------------------------------------

  private handleHealth(_req: ExpressRequest, res: express.Response): void {
    res.json({
      status: 'healthy',
      protocol: 'a2a',
      protocolVersion: '0.3',
      agentDID: this.agentCard.id,
      agentName: this.agentCard.name,
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  }

  // -----------------------------------------------------------------------
  // Message handlers
  // -----------------------------------------------------------------------

  private async handleSendMessage(req: AuthenticatedRequest, res: express.Response): Promise<void> {
    try {
      const { message, contextId } = this.parseMessageRequest(req);

      // Attach AgentPass identity context
      const metadata: Record<string, unknown> = {};
      if (req.agentpass?.did && req.agentpass.did !== 'anonymous') {
        metadata['x-agentpass-requester-did'] = req.agentpass.did;
        metadata['x-agentpass-credential-id'] = req.agentpass.credentialId;
        metadata.credential = req.agentpass;
      }

      const task = await this.taskManager.sendMessage(message, contextId, metadata);

      res.status(200).json(this.formatTaskResponse(task));
    } catch (err: any) {
      // LOW-1 FIX: Sanitize error messages
      res.status(400).json(this.formatError(-32600, 'Invalid message request'));
    }
  }

  private async handleSendStreamingMessage(req: AuthenticatedRequest, res: express.Response): Promise<void> {
    try {
      const { message, contextId } = this.parseMessageRequest(req);

      const metadata: Record<string, unknown> = {};
      if (req.agentpass?.did && req.agentpass.did !== 'anonymous') {
        metadata['x-agentpass-requester-did'] = req.agentpass.did;
        metadata['x-agentpass-credential-id'] = req.agentpass.credentialId;
      }

      const task = await this.taskManager.sendMessage(message, contextId, metadata);

      // Set up SSE
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');

      // Send initial task
      res.write(`data: ${JSON.stringify({ type: 'task', task: this.formatTaskResponse(task) })}\n\n`);

      // Subscribe to updates
      const unsubscribe = this.taskManager.subscribe(task.id, {
        onStatusUpdate: (event) => {
          res.write(`data: ${JSON.stringify({ type: 'status', ...event })}\n\n`);

          // Close on terminal states
          const terminal: TaskState[] = ['completed', 'failed', 'canceled', 'rejected'];
          if (terminal.includes(event.status.state)) {
            res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
            res.end();
            unsubscribe();
          }
        },
        onArtifactUpdate: (event) => {
          res.write(`data: ${JSON.stringify({ type: 'artifact', ...event })}\n\n`);
        },
      });

      // Clean up on client disconnect
      req.on('close', () => {
        unsubscribe();
      });
    } catch (err: any) {
      // LOW-1 FIX: Sanitize error messages
      res.status(400).json(this.formatError(-32600, 'Invalid streaming message request'));
    }
  }

  // -----------------------------------------------------------------------
  // Task handlers
  // -----------------------------------------------------------------------

  private handleGetTask(req: ExpressRequest, res: express.Response): void {
    try {
      const task = this.taskManager.getTask(req.params.id);
      res.json(this.formatTaskResponse(task));
    } catch (err: any) {
      if (err instanceof TaskNotFoundError) {
        res.status(404).json(this.formatError(-32001, 'Task not found'));
      } else {
        res.status(500).json(this.formatError(-32603, 'Internal error'));
      }
    }
  }

  private handleListTasks(req: ExpressRequest, res: express.Response): void {
    // PUB-LOW-7 FIX: Validate and bound query parameters
    let limit: number | undefined;
    let offset: number | undefined;

    if (req.query.limit) {
      limit = parseInt(req.query.limit as string);
      if (isNaN(limit) || limit < 1) limit = 50;
      if (limit > 1000) limit = 1000;
    }
    if (req.query.offset) {
      offset = parseInt(req.query.offset as string);
      if (isNaN(offset) || offset < 0) offset = 0;
    }

    const { tasks, total } = this.taskManager.listTasks({
      contextId: req.query.contextId as string,
      status: req.query.status as TaskState,
      limit,
      offset,
    });

    res.json({
      tasks: tasks.map((t) => this.formatTaskResponse(t)),
      total,
    });
  }

  private handleCancelTask(req: ExpressRequest, res: express.Response): void {
    try {
      const task = this.taskManager.cancelTask(req.params.id);
      res.json(this.formatTaskResponse(task));
    } catch (err: any) {
      if (err instanceof TaskNotFoundError) {
        res.status(404).json(this.formatError(-32001, 'Task not found'));
      } else if (err instanceof TaskNotCancelableError) {
        res.status(409).json(this.formatError(-32002, 'Task cannot be canceled'));
      } else {
        res.status(500).json(this.formatError(-32603, 'Internal error'));
      }
    }
  }

  private handleSubscribeToTask(req: ExpressRequest, res: express.Response): void {
    try {
      const taskId = req.params.id;

      // Verify task exists
      this.taskManager.getTask(taskId);

      // Set up SSE
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');

      const unsubscribe = this.taskManager.subscribe(taskId, {
        onStatusUpdate: (event) => {
          res.write(`data: ${JSON.stringify({ type: 'status', ...event })}\n\n`);

          const terminal: TaskState[] = ['completed', 'failed', 'canceled', 'rejected'];
          if (terminal.includes(event.status.state)) {
            res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
            res.end();
            unsubscribe();
          }
        },
        onArtifactUpdate: (event) => {
          res.write(`data: ${JSON.stringify({ type: 'artifact', ...event })}\n\n`);
        },
      });

      req.on('close', () => {
        unsubscribe();
      });
    } catch (err: any) {
      if (err instanceof TaskNotFoundError) {
        res.status(404).json(this.formatError(-32001, 'Task not found'));
      } else {
        res.status(500).json(this.formatError(-32603, 'Internal error'));
      }
    }
  }

  // -----------------------------------------------------------------------
  // Push notification handlers
  // -----------------------------------------------------------------------

  private handleCreatePushConfig(req: ExpressRequest, res: express.Response): void {
    try {
      // LOW-3 FIX: Validate push notification URL to prevent SSRF
      const pushUrl = req.body.url;
      if (pushUrl) {
        try {
          const parsed = new URL(pushUrl);
          // Block internal/private network URLs
          if (parsed.hostname === 'localhost' ||
              parsed.hostname === '127.0.0.1' ||
              parsed.hostname === '0.0.0.0' ||
              parsed.hostname === '::1' ||
              parsed.hostname.endsWith('.local') ||
              parsed.hostname.startsWith('10.') ||
              parsed.hostname.startsWith('192.168.') ||
              /^172\.(1[6-9]|2\d|3[01])\./.test(parsed.hostname) ||
              parsed.hostname.startsWith('169.254.') ||
              parsed.protocol === 'file:') {
            res.status(400).json(this.formatError(-32600, 'Push notification URL must be a public HTTPS endpoint'));
            return;
          }
          if (parsed.protocol !== 'https:') {
            res.status(400).json(this.formatError(-32600, 'Push notification URL must use HTTPS'));
            return;
          }
        } catch {
          res.status(400).json(this.formatError(-32600, 'Invalid push notification URL'));
          return;
        }
      }

      const config = this.taskManager.createPushConfig({
        taskId: req.params.taskId,
        url: pushUrl,
        token: req.body.token,
        authentication: req.body.authentication,
        events: req.body.events,
      });
      res.status(201).json(config);
    } catch (err: any) {
      if (err instanceof TaskNotFoundError) {
        // PUB-LOW FIX: Don't leak task ID in error message
        res.status(404).json(this.formatError(-32001, 'Task not found'));
      } else {
        // LOW-1 FIX: Don't leak internal error details
        res.status(500).json(this.formatError(-32603, 'Push config creation failed'));
      }
    }
  }

  private handleListPushConfigs(req: ExpressRequest, res: express.Response): void {
    try {
      const configs = this.taskManager.getPushConfigs(req.params.taskId);
      res.json({ configs });
    } catch (err: any) {
      if (err instanceof TaskNotFoundError) {
        res.status(404).json(this.formatError(-32001, 'Task not found'));
      } else {
        res.status(500).json(this.formatError(-32603, 'Internal error'));
      }
    }
  }

  private handleGetPushConfig(req: ExpressRequest, res: express.Response): void {
    try {
      const configs = this.taskManager.getPushConfigs(req.params.taskId);
      const config = configs.find((c) => c.id === req.params.id);
      if (!config) {
        res.status(404).json(this.formatError(-32001, 'Push config not found'));
        return;
      }
      res.json(config);
    } catch (err: any) {
      res.status(500).json(this.formatError(-32603, 'Internal error'));
    }
  }

  private handleDeletePushConfig(req: ExpressRequest, res: express.Response): void {
    try {
      this.taskManager.deletePushConfig(req.params.taskId, req.params.id);
      res.status(204).send();
    } catch (err: any) {
      res.status(500).json(this.formatError(-32603, 'Internal error'));
    }
  }

  // -----------------------------------------------------------------------
  // JSON-RPC endpoint (unified)
  // -----------------------------------------------------------------------

  private async handleJsonRpc(req: AuthenticatedRequest, res: express.Response): Promise<void> {
    const body = req.body as JsonRpcRequest;

    if (body.jsonrpc !== '2.0' || !body.method) {
      res.status(400).json(this.formatJsonRpcError(body?.id, -32600, 'Invalid JSON-RPC request'));
      return;
    }

    try {
      let result: unknown;

      switch (body.method) {
        case 'SendMessage':
        case 'messages/send': {
          const params = body.params ?? {};
          const message = this.buildMessage(params.message as Record<string, unknown>);
          const metadata: Record<string, unknown> = {};
          if (req.agentpass?.did && req.agentpass.did !== 'anonymous') {
            metadata['x-agentpass-requester-did'] = req.agentpass.did;
          }
          const task = await this.taskManager.sendMessage(
            message,
            params.contextId as string,
            metadata
          );
          result = this.formatTaskResponse(task);
          break;
        }

        case 'GetTask':
        case 'tasks/get': {
          const task = this.taskManager.getTask(body.params?.id as string);
          result = this.formatTaskResponse(task);
          break;
        }

        case 'ListTasks':
        case 'tasks/list': {
          // PUB-MED-7 FIX: Validate params instead of passing raw `as any`
          const listParams = body.params ?? {};
          const listLimit = typeof listParams.limit === 'number'
            ? Math.min(Math.max(1, listParams.limit), 1000) : undefined;
          const listOffset = typeof listParams.offset === 'number'
            ? Math.max(0, listParams.offset) : undefined;
          result = this.taskManager.listTasks({
            contextId: typeof listParams.contextId === 'string' ? listParams.contextId : undefined,
            status: typeof listParams.status === 'string' ? listParams.status as TaskState : undefined,
            limit: listLimit,
            offset: listOffset,
          });
          break;
        }

        case 'CancelTask':
        case 'tasks/cancel': {
          const task = this.taskManager.cancelTask(body.params?.id as string);
          result = this.formatTaskResponse(task);
          break;
        }

        case 'GetExtendedAgentCard':
        case 'agent/extendedCard': {
          if (!req.agentpass?.verified) {
            res.json(this.formatJsonRpcError(body.id, -32010, 'Authentication required'));
            return;
          }
          result = { ...this.agentCard, 'x-agentpass-extended': true };
          break;
        }

        default:
          res.json(this.formatJsonRpcError(body.id, -32601, `Method not found: ${body.method}`));
          return;
      }

      res.json({
        jsonrpc: '2.0',
        id: body.id,
        result,
      });
    } catch (err: any) {
      // LOW-1 FIX: Sanitize error messages in JSON-RPC responses
      if (err instanceof TaskNotFoundError) {
        res.json(this.formatJsonRpcError(body.id, -32001, 'Task not found'));
      } else if (err instanceof TaskNotCancelableError) {
        res.json(this.formatJsonRpcError(body.id, -32002, 'Task cannot be canceled'));
      } else {
        res.json(this.formatJsonRpcError(body.id, -32603, 'Internal error'));
      }
    }
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private parseMessageRequest(req: ExpressRequest): { message: Message; contextId?: string } {
    const body = req.body;

    // Support both direct message format and JSON-RPC params
    const params = body.params ?? body;

    const message = this.buildMessage(params.message ?? params);
    const contextId = params.contextId;

    return { message, contextId };
  }

  private buildMessage(data: Record<string, unknown> | undefined): Message {
    if (!data) {
      throw new Error('Message is required');
    }

    // If it's already a proper Message
    if (data.id && data.role && Array.isArray(data.parts)) {
      return data as unknown as Message;
    }

    // Build from simple text
    const parts: Part[] = [];

    if (data.text || data.content) {
      parts.push({ type: 'text', text: (data.text ?? data.content) as string });
    }

    if (data.parts && Array.isArray(data.parts)) {
      parts.push(...(data.parts as Part[]));
    }

    if (parts.length === 0) {
      // Try to use the whole body as text
      parts.push({ type: 'text', text: JSON.stringify(data) });
    }

    return {
      id: (data.id as string) ?? uuidv4(),
      role: (data.role as 'user' | 'agent') ?? 'user',
      parts,
      metadata: data.metadata as Record<string, unknown>,
    };
  }

  private formatTaskResponse(task: Task): Record<string, unknown> {
    return {
      id: task.id,
      contextId: task.contextId,
      status: task.status,
      messages: task.messages,
      artifacts: task.artifacts,
      metadata: task.metadata,
      createdAt: task.createdAt,
      updatedAt: task.updatedAt,
      // Include AgentPass extensions
      ...(task['x-agentpass-requester-did'] && {
        'x-agentpass-requester-did': task['x-agentpass-requester-did'],
      }),
      ...(task['x-agentpass-responder-did'] && {
        'x-agentpass-responder-did': task['x-agentpass-responder-did'],
      }),
      ...(task['x-agentpass-credential-id'] && {
        'x-agentpass-credential-id': task['x-agentpass-credential-id'],
      }),
    };
  }

  private formatError(code: number, message: string): Record<string, unknown> {
    return { error: { code, message } };
  }

  private formatJsonRpcError(
    id: string | number | undefined,
    code: number,
    message: string
  ): JsonRpcResponse {
    return {
      jsonrpc: '2.0',
      id: id ?? 0,
      error: { code, message },
    };
  }
}

// -------------------------------------------------------------------------
// Default task handler
// -------------------------------------------------------------------------

const defaultTaskHandler: TaskHandler = async (task, message, context) => {
  const text = message.parts
    .filter((p): p is { type: 'text'; text: string } => p.type === 'text')
    .map((p) => p.text)
    .join('\n');

  return {
    status: 'completed' as TaskState,
    messages: [
      {
        id: uuidv4(),
        role: 'agent' as const,
        parts: [
          {
            type: 'text' as const,
            text:
              `Received your message. This is the default AgentPass A2A handler. ` +
              `Configure a custom taskHandler to process messages.\n\n` +
              `Your message: "${text.slice(0, 200)}"\n` +
              `Agent DID: ${task['x-agentpass-responder-did'] ?? 'not set'}\n` +
              `Requester DID: ${context.requesterDID ?? 'anonymous'}`,
          },
        ],
      },
    ],
  };
};
