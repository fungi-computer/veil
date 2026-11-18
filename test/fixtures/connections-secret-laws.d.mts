import type {
  ConnectionSubject,
  ConnectionUsage,
  ConnectionView,
  EgressRef,
  HttpDestinations,
  McpRefusal,
  McpRequestData,
  Placement,
} from "@fungi.computer/veil/connections";

/** One Connections owner, seen only through its public methods. */
export type SecretOwner = Readonly<{
  /** A unique fake provider-shaped canary for this run. */
  secret: string;
  subjects: Readonly<{
    agent: ConnectionSubject;
    computer: ConnectionSubject;
    app: ConnectionSubject;
    teamKey: ConnectionSubject;
    /** A team key that does not exist, or is no longer live. */
    deadKey: ConnectionSubject;
  }>;
  add: (input: {
    name: string;
    destinations: HttpDestinations;
    placement: Placement;
    secret: string;
  }) => Promise<string>;
  list: () => Promise<readonly ConnectionView[]>;
  /** A refusal is the owner's typed refusal code, never a thrown message. */
  grant: (
    connectionId: string,
    subject: ConnectionSubject,
  ) => Promise<EgressRef | Readonly<{ refusal: string }>>;
  ungrant: (connectionId: string, subject: ConnectionSubject) => Promise<void>;
  revoke: (connectionId: string) => Promise<void>;
  send: (
    subject: ConnectionSubject,
    ref: EgressRef,
    data: McpRequestData,
  ) => Promise<Response | McpRefusal>;
  usage: (connectionId: string) => Promise<readonly ConnectionUsage[]>;
  /** Absent where the owner has no lesser grantor (Oyster's single owner). */
  demote?: () => void;
  /**
   * End one subject the way its host does: delete the Agent or Computer,
   * revoke or expire the key. Its grant row stays; only liveness changes.
   */
  end: (subject: ConnectionSubject) => void;
  /** Every request the owner sent upstream. */
  sent: () => readonly Request[];
  /** Every byte the owner stores: its SQLite cells and sealed records. */
  storedBytes: () => Promise<Uint8Array>;
}>;

export function proveSecretOwner(owner: SecretOwner): Promise<void>;
