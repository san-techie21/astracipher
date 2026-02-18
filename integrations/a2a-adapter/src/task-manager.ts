/**
 * Task Manager
 *
 * Manages the A2A task lifecycle:
 *   submitted → working → (input-required?) → completed / failed
 *
 * Each task is tracked in memory with full message history and artifacts.
 * The task handler is user-provided — this module handles protocol concerns.
 */

import { v4 as uuidv4 } from 'uuid';
import type {
  Task,
  TaskState,
  TaskStatus,
  Message,
  Artifact,
  Part,
  TaskHandler,
  TaskHandlerContext,
  TaskStatusUpdateEvent,
  TaskArtifactUpdateEvent,
  PushNotificationConfig,
} from './types.js';

interface TaskSubscriber {
  onStatusUpdate: (event: TaskStatusUpdateEvent) => void;
  onArtifactUpdate: (event: TaskArtifactUpdateEvent) => void;
}

// PUB-LOW-8 FIX: Maximum tasks retained in memory + TTL eviction
const MAX_TASKS = 10000;
const TASK_TTL_MS = 60 * 60 * 1000; // 1 hour for completed tasks
const EVICTION_INTERVAL_MS = 5 * 60 * 1000; // Run eviction every 5 minutes

export class TaskManager {
  private tasks = new Map<string, Task>();
  private subscribers = new Map<string, TaskSubscriber[]>();
  private pushConfigs = new Map<string, PushNotificationConfig[]>();
  private handler: TaskHandler;
  private evictionTimer: ReturnType<typeof setInterval>;

  constructor(handler: TaskHandler) {
    this.handler = handler;
    // PUB-LOW-8 FIX: Periodic eviction of completed/failed tasks
    this.evictionTimer = setInterval(() => this.evictStaleTasks(), EVICTION_INTERVAL_MS);
    // Don't block process exit
    if (this.evictionTimer.unref) this.evictionTimer.unref();
  }

  /**
   * Stop the eviction timer (for graceful shutdown)
   */
  destroy(): void {
    clearInterval(this.evictionTimer);
  }

  /**
   * Evict completed/failed tasks older than TTL, cap total at MAX_TASKS
   */
  private evictStaleTasks(): void {
    const now = Date.now();
    const terminal: TaskState[] = ['completed', 'failed', 'canceled', 'rejected'];

    for (const [id, task] of this.tasks) {
      if (terminal.includes(task.status.state)) {
        const age = now - new Date(task.updatedAt).getTime();
        if (age > TASK_TTL_MS) {
          this.tasks.delete(id);
          this.subscribers.delete(id);
          this.pushConfigs.delete(id);
        }
      }
    }

    // Hard cap: evict oldest tasks if over limit
    if (this.tasks.size > MAX_TASKS) {
      const sorted = Array.from(this.tasks.entries())
        .sort((a, b) => a[1].createdAt.localeCompare(b[1].createdAt));
      const toRemove = sorted.slice(0, this.tasks.size - MAX_TASKS);
      for (const [id] of toRemove) {
        this.tasks.delete(id);
        this.subscribers.delete(id);
        this.pushConfigs.delete(id);
      }
    }
  }

  /**
   * Create and execute a new task from an incoming message
   */
  async sendMessage(
    message: Message,
    contextId?: string,
    metadata?: Record<string, unknown>
  ): Promise<Task> {
    const taskId = uuidv4();
    const now = new Date().toISOString();

    const task: Task = {
      id: taskId,
      contextId: contextId ?? uuidv4(),
      status: { state: 'submitted', timestamp: now },
      messages: [message],
      artifacts: [],
      metadata: metadata ?? {},
      createdAt: now,
      updatedAt: now,
    };

    // Copy AstraCipher extensions from metadata
    if (metadata?.['x-astracipher-requester-did']) {
      task['x-astracipher-requester-did'] = metadata['x-astracipher-requester-did'] as string;
    }
    if (metadata?.['x-astracipher-credential-id']) {
      task['x-astracipher-credential-id'] = metadata['x-astracipher-credential-id'] as string;
    }

    this.tasks.set(taskId, task);

    // Execute asynchronously — don't block the response
    this.executeTask(task, message).catch((err) => {
      // PUB-MED-1 FIX: Don't leak internal error details in task status
      console.error(`Task ${taskId} failed:`, err);
      this.updateTaskStatus(taskId, 'failed', 'Internal processing error');
    });

    return task;
  }

  /**
   * Send a message to an existing task (multi-turn conversation)
   */
  async sendMessageToTask(taskId: string, message: Message): Promise<Task> {
    const task = this.tasks.get(taskId);
    if (!task) throw new TaskNotFoundError(taskId);

    const terminal: TaskState[] = ['completed', 'failed', 'canceled', 'rejected'];
    if (terminal.includes(task.status.state)) {
      throw new Error(`Task ${taskId} is in terminal state: ${task.status.state}`);
    }

    task.messages = task.messages ?? [];
    task.messages.push(message);
    task.updatedAt = new Date().toISOString();

    // Re-execute with the new message
    this.executeTask(task, message).catch((err) => {
      // PUB-MED-2 FIX: Don't leak internal error details in task status
      console.error(`Task ${taskId} re-execution failed:`, err);
      this.updateTaskStatus(taskId, 'failed', 'Internal processing error');
    });

    return task;
  }

  /**
   * Get a task by ID
   */
  getTask(taskId: string): Task {
    const task = this.tasks.get(taskId);
    if (!task) throw new TaskNotFoundError(taskId);
    return task;
  }

  /**
   * List tasks with optional filters
   */
  listTasks(filters?: {
    contextId?: string;
    status?: TaskState;
    limit?: number;
    offset?: number;
  }): { tasks: Task[]; total: number } {
    let tasks = Array.from(this.tasks.values());

    if (filters?.contextId) {
      tasks = tasks.filter((t) => t.contextId === filters.contextId);
    }
    if (filters?.status) {
      tasks = tasks.filter((t) => t.status.state === filters.status);
    }

    // Sort by creation (newest first)
    tasks.sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    const total = tasks.length;
    const offset = filters?.offset ?? 0;
    const limit = filters?.limit ?? 50;

    return {
      tasks: tasks.slice(offset, offset + limit),
      total,
    };
  }

  /**
   * Cancel a running task
   */
  cancelTask(taskId: string): Task {
    const task = this.tasks.get(taskId);
    if (!task) throw new TaskNotFoundError(taskId);

    const cancelable: TaskState[] = ['submitted', 'working', 'input-required'];
    if (!cancelable.includes(task.status.state)) {
      throw new TaskNotCancelableError(taskId, task.status.state);
    }

    this.updateTaskStatus(taskId, 'canceled', 'Canceled by client');
    return this.tasks.get(taskId)!;
  }

  /**
   * Subscribe to task updates (for SSE streaming)
   */
  subscribe(taskId: string, subscriber: TaskSubscriber): () => void {
    if (!this.tasks.has(taskId)) throw new TaskNotFoundError(taskId);

    const subs = this.subscribers.get(taskId) ?? [];
    subs.push(subscriber);
    this.subscribers.set(taskId, subs);

    // Return unsubscribe function
    return () => {
      const current = this.subscribers.get(taskId) ?? [];
      this.subscribers.set(
        taskId,
        current.filter((s) => s !== subscriber)
      );
    };
  }

  /**
   * Configure push notifications for a task
   */
  createPushConfig(config: Omit<PushNotificationConfig, 'id' | 'createdAt'>): PushNotificationConfig {
    if (!this.tasks.has(config.taskId)) throw new TaskNotFoundError(config.taskId);

    const pushConfig: PushNotificationConfig = {
      ...config,
      id: uuidv4(),
      createdAt: new Date().toISOString(),
    };

    const configs = this.pushConfigs.get(config.taskId) ?? [];
    configs.push(pushConfig);
    this.pushConfigs.set(config.taskId, configs);

    return pushConfig;
  }

  /**
   * Get push configs for a task
   */
  getPushConfigs(taskId: string): PushNotificationConfig[] {
    if (!this.tasks.has(taskId)) throw new TaskNotFoundError(taskId);
    return this.pushConfigs.get(taskId) ?? [];
  }

  /**
   * Delete a push config
   */
  deletePushConfig(taskId: string, configId: string): void {
    const configs = this.pushConfigs.get(taskId) ?? [];
    this.pushConfigs.set(
      taskId,
      configs.filter((c) => c.id !== configId)
    );
  }

  // -----------------------------------------------------------------------
  // Private methods
  // -----------------------------------------------------------------------

  private async executeTask(task: Task, message: Message): Promise<void> {
    const taskId = task.id;

    // Transition to working
    this.updateTaskStatus(taskId, 'working');

    const context: TaskHandlerContext = {
      requesterDID: task['x-astracipher-requester-did'],
      requesterCredential: task.metadata?.credential as Record<string, unknown>,
      updateStatus: (state, reason) => {
        this.updateTaskStatus(taskId, state, reason);
      },
      emitArtifact: (artifact) => {
        this.addArtifact(taskId, artifact);
      },
    };

    try {
      const result = await this.handler(task, message, context);

      // Add response messages
      if (result.messages) {
        task.messages = task.messages ?? [];
        task.messages.push(...result.messages);
      }

      // Add artifacts
      if (result.artifacts) {
        task.artifacts = task.artifacts ?? [];
        task.artifacts.push(...result.artifacts);
        for (const artifact of result.artifacts) {
          this.notifyArtifactUpdate(taskId, artifact);
        }
      }

      // Final status
      this.updateTaskStatus(taskId, result.status, result.reason);
    } catch (error: any) {
      // PUB-MED-3 FIX: Don't expose handler exception details to clients
      console.error(`Task handler error for ${taskId}:`, error);
      this.updateTaskStatus(taskId, 'failed', 'Task handler encountered an error');
    }
  }

  private updateTaskStatus(taskId: string, state: TaskState, reason?: string): void {
    const task = this.tasks.get(taskId);
    if (!task) return;

    const now = new Date().toISOString();
    task.status = { state, timestamp: now, reason };
    task.updatedAt = now;

    // Notify subscribers
    const event: TaskStatusUpdateEvent = {
      taskId,
      status: task.status,
      timestamp: now,
    };

    const subs = this.subscribers.get(taskId) ?? [];
    for (const sub of subs) {
      try {
        sub.onStatusUpdate(event);
      } catch {
        // Subscriber errors shouldn't crash the task
      }
    }

    // Fire push notifications
    this.firePushNotifications(taskId, event);
  }

  private addArtifact(taskId: string, artifact: Artifact): void {
    const task = this.tasks.get(taskId);
    if (!task) return;

    task.artifacts = task.artifacts ?? [];
    task.artifacts.push(artifact);
    task.updatedAt = new Date().toISOString();

    this.notifyArtifactUpdate(taskId, artifact);
  }

  private notifyArtifactUpdate(taskId: string, artifact: Artifact): void {
    const event: TaskArtifactUpdateEvent = {
      taskId,
      artifact,
      timestamp: new Date().toISOString(),
    };

    const subs = this.subscribers.get(taskId) ?? [];
    for (const sub of subs) {
      try {
        sub.onArtifactUpdate(event);
      } catch {
        // Subscriber errors shouldn't crash the task
      }
    }
  }

  private async firePushNotifications(
    taskId: string,
    event: TaskStatusUpdateEvent
  ): Promise<void> {
    const configs = this.pushConfigs.get(taskId) ?? [];

    for (const config of configs) {
      // Only fire for subscribed events
      if (config.events && !config.events.includes(event.status.state)) {
        continue;
      }

      try {
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };

        if (config.authentication) {
          switch (config.authentication.type) {
            case 'bearer':
              headers['Authorization'] = `Bearer ${config.authentication.credentials}`;
              break;
            case 'apiKey':
              headers['X-API-Key'] = config.authentication.credentials;
              break;
          }
        }

        await fetch(config.url, {
          method: 'POST',
          headers,
          body: JSON.stringify(event),
        });
      } catch {
        // Best-effort push; log but don't fail
        console.warn(`Push notification failed for task ${taskId} to ${config.url}`);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------

export class TaskNotFoundError extends Error {
  code = -32001;
  constructor(taskId: string) {
    super(`Task not found: ${taskId}`);
    this.name = 'TaskNotFoundError';
  }
}

export class TaskNotCancelableError extends Error {
  code = -32002;
  constructor(taskId: string, state: string) {
    super(`Task ${taskId} cannot be canceled (state: ${state})`);
    this.name = 'TaskNotCancelableError';
  }
}
