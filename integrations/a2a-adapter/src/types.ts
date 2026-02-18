/**
 * A2A Protocol Types
 *
 * Type definitions for Google's Agent-to-Agent (A2A) protocol v0.3.
 * These types define the Agent Card format, task lifecycle, messaging,
 * and JSON-RPC methods used for inter-agent communication.
 *
 * @see https://a2a-protocol.org/latest/specification/
 */

// ---------------------------------------------------------------------------
// Agent Card — Discovery & Capability Advertisement
// ---------------------------------------------------------------------------

export interface AgentCard {
  /** Unique agent identifier (DID in AstraCipher context) */
  id: string;
  /** Human-readable agent name */
  name: string;
  /** Agent description */
  description?: string;
  /** Organization providing the agent */
  provider?: AgentProvider;
  /** A2A service endpoint URL */
  url: string;
  /** Protocol version (e.g., "0.3") */
  version: string;
  /** Supported capabilities */
  capabilities?: AgentCapabilities;
  /** Agent skills / available operations */
  skills: AgentSkill[];
  /** Protocol bindings */
  interfaces?: AgentInterface[];
  /** Security requirements (references to securitySchemes) */
  security?: Record<string, string[]>[];
  /** Authentication scheme definitions */
  securitySchemes?: Record<string, SecurityScheme>;
  /** Default accepted input MIME types */
  defaultInputModes?: string[];
  /** Default output MIME types */
  defaultOutputModes?: string[];
  /** Link to human-readable documentation */
  documentationUrl?: string;
  /** Agent card cryptographic signature */
  signature?: AgentCardSignature;

  // -- AstraCipher extensions --
  /** AstraCipher DID identifier */
  'x-astracipher-did'?: string;
  /** AstraCipher credential ID */
  'x-astracipher-credential'?: string;
  /** Post-quantum signature algorithm used */
  'x-astracipher-pqc-algorithm'?: string;
  /** Trust level from AstraCipher credential (1-10) */
  'x-astracipher-trust-level'?: number;
  /** Compliance frameworks this agent satisfies */
  'x-astracipher-compliance'?: string[];
}

export interface AgentProvider {
  name: string;
  contactEmail?: string;
  url?: string;
}

export interface AgentCapabilities {
  /** Supports SSE streaming */
  streaming?: boolean;
  /** Supports webhook push notifications */
  pushNotifications?: boolean;
  /** Has extended (authenticated) agent card */
  extendedAgentCard?: boolean;
}

export interface AgentSkill {
  id: string;
  name: string;
  description?: string;
  inputParameters?: Record<string, unknown>;
  outputFormat?: string;
  inputModes?: string[];
  outputModes?: string[];
  tags?: string[];
}

export interface AgentInterface {
  protocol: 'json-rpc' | 'grpc' | 'http';
  url?: string;
}

export interface SecurityScheme {
  type: 'apiKey' | 'http' | 'oauth2' | 'openIdConnect' | 'mutualTls';
  name?: string;
  in?: 'header' | 'query';
  scheme?: string;
  bearerFormat?: string;
  flows?: Record<string, unknown>;
  openIdConnectUrl?: string;
  description?: string;
}

export interface AgentCardSignature {
  publicKey: string;
  signature: string;
  algorithm: 'RS256' | 'ES256' | 'EdDSA' | 'ML-DSA-65' | 'hybrid-pqc';
}

// ---------------------------------------------------------------------------
// Task Lifecycle
// ---------------------------------------------------------------------------

export type TaskState =
  | 'submitted'
  | 'working'
  | 'input-required'
  | 'auth-required'
  | 'completed'
  | 'failed'
  | 'canceled'
  | 'rejected';

export interface TaskStatus {
  state: TaskState;
  timestamp: string;
  reason?: string;
}

export interface Task {
  id: string;
  contextId?: string;
  status: TaskStatus;
  messages?: Message[];
  artifacts?: Artifact[];
  metadata?: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;

  // -- AstraCipher extensions --
  /** DID of the requesting agent */
  'x-astracipher-requester-did'?: string;
  /** DID of the responding agent */
  'x-astracipher-responder-did'?: string;
  /** Credential used to authorize this task */
  'x-astracipher-credential-id'?: string;
}

// ---------------------------------------------------------------------------
// Messages & Content
// ---------------------------------------------------------------------------

export type Role = 'user' | 'agent';

export interface Message {
  id: string;
  role: Role;
  parts: Part[];
  metadata?: Record<string, unknown>;
}

export type Part = TextPart | FilePart | DataPart;

export interface TextPart {
  type: 'text';
  text: string;
}

export interface FilePart {
  type: 'file';
  file: {
    uri?: string;
    bytes?: string;
    mediaType?: string;
    filename?: string;
  };
}

export interface DataPart {
  type: 'data';
  data: Record<string, unknown>;
}

export interface Artifact {
  id: string;
  name?: string;
  parts: Part[];
  mediaType?: string;
  append?: boolean;
  lastChunk?: boolean;
}

// ---------------------------------------------------------------------------
// Streaming Events
// ---------------------------------------------------------------------------

export interface TaskStatusUpdateEvent {
  taskId: string;
  status: TaskStatus;
  message?: Message;
  timestamp: string;
}

export interface TaskArtifactUpdateEvent {
  taskId: string;
  artifact: Artifact;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// JSON-RPC Messages
// ---------------------------------------------------------------------------

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: JsonRpcError;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

// A2A-specific error codes
export const A2A_ERRORS = {
  TASK_NOT_FOUND: { code: -32001, message: 'Task not found' },
  TASK_NOT_CANCELABLE: { code: -32002, message: 'Task is not cancelable' },
  PUSH_NOT_SUPPORTED: { code: -32003, message: 'Push notifications not supported' },
  UNSUPPORTED_OPERATION: { code: -32004, message: 'Unsupported operation' },
  CONTENT_TYPE_NOT_SUPPORTED: { code: -32005, message: 'Content type not supported' },
  VERSION_NOT_SUPPORTED: { code: -32006, message: 'Protocol version not supported' },
  AUTH_REQUIRED: { code: -32010, message: 'Authentication required' },
  CREDENTIAL_INVALID: { code: -32011, message: 'AstraCipher credential invalid' },
  PERMISSION_DENIED: { code: -32012, message: 'Insufficient permissions' },
} as const;

// ---------------------------------------------------------------------------
// Push Notifications
// ---------------------------------------------------------------------------

export interface PushNotificationConfig {
  id: string;
  taskId: string;
  url: string;
  token?: string;
  authentication?: {
    type: 'bearer' | 'apiKey' | 'hmac';
    credentials: string;
  };
  events?: TaskState[];
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Adapter Configuration
// ---------------------------------------------------------------------------

export interface A2AAdapterConfig {
  /** AstraCipher server URL */
  astracipherUrl: string;
  /** Port for the A2A HTTP server */
  port?: number;
  /** Host to bind (default: 0.0.0.0) */
  host?: string;
  /** Public URL where this adapter is reachable */
  publicUrl?: string;
  /** AstraCipher API key for server communication */
  apiKey?: string;
  /** AstraCipher network (testnet/mainnet) */
  network?: 'testnet' | 'mainnet';
  /** Enable SSE streaming */
  enableStreaming?: boolean;
  /** Enable push notifications */
  enablePushNotifications?: boolean;
  /** Custom task handler */
  taskHandler?: TaskHandler;
}

/**
 * TaskHandler is the user-provided function that processes incoming A2A tasks.
 * The adapter handles all protocol, identity, and auth concerns;
 * the handler just does the agent's actual work.
 */
export type TaskHandler = (
  task: Task,
  message: Message,
  context: TaskHandlerContext
) => Promise<TaskHandlerResult>;

export interface TaskHandlerContext {
  /** DID of the requesting agent (if authenticated via AstraCipher) */
  requesterDID?: string;
  /** Verified credential of the requester */
  requesterCredential?: Record<string, unknown>;
  /** Send a status update mid-task */
  updateStatus: (state: TaskState, reason?: string) => void;
  /** Emit an artifact */
  emitArtifact: (artifact: Artifact) => void;
}

export interface TaskHandlerResult {
  status: TaskState;
  messages?: Message[];
  artifacts?: Artifact[];
  reason?: string;
}
