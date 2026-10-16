import { ScryptPasswordHasher } from './password-hasher';

describe('ScryptPasswordHasher', () => {
  it('stores and verifies the approved versioned scrypt record', async () => {
    const hasher = new ScryptPasswordHasher();
    const password = 'correct horse battery staple';
    const record = await hasher.hash(password);

    expect(record).toMatch(/^scrypt\$v1\$131072\$8\$1\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{86}$/);
    await expect(hasher.verify(password, record)).resolves.toBe(true);
    await expect(hasher.verify('different password', record)).resolves.toBe(false);
  });

  it.each([
    [
      'hash',
      async (hasher: ScryptPasswordHasher, record: string): Promise<unknown> =>
        hasher.hash('password'),
    ],
    [
      'verify',
      async (hasher: ScryptPasswordHasher, record: string): Promise<unknown> =>
        hasher.verify('password', record),
    ],
    [
      'verifyDummy',
      async (hasher: ScryptPasswordHasher, record: string): Promise<unknown> =>
        hasher.verifyDummy('password'),
    ],
  ])('rejects the exact scoped scrypt callback error from %s', async (_method, operation) => {
    const marker = new Error(`SCF callback ${_method}`);
    let loaded: IsolatedHasher | undefined;
    try {
      loaded = await loadIsolatedHasher((_actualScrypt, calls) => (...arguments_) => {
        calls.increment();
        const callback = arguments_.at(-1);
        if (typeof callback !== 'function') throw new Error('Expected scrypt callback.');
        queueMicrotask(() => callback(marker, Buffer.alloc(64)));
      });
      const hasher = new loaded.Hasher();
      const record = await new ScryptPasswordHasher().hash('valid record password');
      await expect(operation(hasher, record)).rejects.toBe(marker);
      expect(loaded.calls.count()).toBe(1);
    } finally {
      loaded?.restore();
    }
  });

  it('turns a scoped synchronous scrypt throw into a rejected Promise', async () => {
    const marker = new Error('SCF synchronous scrypt throw');
    let loaded: IsolatedHasher | undefined;
    try {
      loaded = await loadIsolatedHasher((_actualScrypt, calls) => () => {
        calls.increment();
        throw marker;
      });
      const hasher = new loaded.Hasher();
      await expect(hasher.hash('password')).rejects.toBe(marker);
      expect(loaded.calls.count()).toBe(1);
    } finally {
      loaded?.restore();
    }
  });
});

type ScryptArguments = Parameters<typeof import('node:crypto').scrypt>;
type ScryptReplacement = (
  actualScrypt: typeof import('node:crypto').scrypt,
  calls: ScopedCallCounter,
) => (...arguments_: ScryptArguments) => void;

interface IsolatedHasher {
  readonly Hasher: typeof ScryptPasswordHasher;
  readonly calls: ScopedCallCounter;
  restore(): void;
}

class ScopedCallCounter {
  private value = 0;

  public increment(): void {
    this.value += 1;
  }

  public count(): number {
    return this.value;
  }
}

async function loadIsolatedHasher(replacement: ScryptReplacement): Promise<IsolatedHasher> {
  const calls = new ScopedCallCounter();
  let Hasher: typeof ScryptPasswordHasher | undefined;
  jest.resetModules();
  jest.doMock('node:crypto', () => {
    const actual = jest.requireActual<typeof import('node:crypto')>('node:crypto');
    return { ...actual, scrypt: replacement(actual.scrypt, calls) };
  });
  try {
    await jest.isolateModulesAsync(async () => {
      const isolated = await import('./password-hasher');
      Hasher = isolated.ScryptPasswordHasher;
    });
    if (Hasher === undefined) throw new Error('Isolated hasher was unavailable.');
    return {
      Hasher,
      calls,
      restore: (): void => {
        jest.dontMock('node:crypto');
        jest.resetModules();
      },
    };
  } catch (error: unknown) {
    jest.dontMock('node:crypto');
    jest.resetModules();
    throw error;
  }
}
