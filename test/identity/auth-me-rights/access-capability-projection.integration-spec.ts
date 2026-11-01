import { AccessCapabilityPersistenceMapper } from '../../../src/modules/identity/infrastructure/persistence/mappers/access-capability.persistence-mapper';

describe('Access capability persistence projection boundary', () => {
  it('accepts only the finite capability values and returns deterministic unique output', () => {
    expect(
      AccessCapabilityPersistenceMapper.toActiveProjection([
        { capability: 'instructor' },
        { capability: 'administrator' },
        { capability: 'instructor' },
        { capability: 'content_moderator' },
      ]),
    ).toEqual({
      kind: 'available',
      projection: { capabilities: ['administrator', 'content_moderator', 'instructor'] },
    });
  });

  it.each([
    [{ capability: 'unknown_capability' }],
    [{ capability: 7 }],
    [null],
    { capability: 'administrator' },
  ])('fails closed for an invalid raw persistence result', (rows: unknown) => {
    expect(AccessCapabilityPersistenceMapper.toActiveProjection(rows)).toEqual({
      kind: 'unavailable',
    });
  });
});
