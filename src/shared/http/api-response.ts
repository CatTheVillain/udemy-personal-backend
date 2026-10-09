export class ApiResponse<T> {
  public readonly data: T;

  public constructor(data: T) {
    this.data = data;
  }
}

export class PaginationMeta {
  public readonly currentPage: number;
  public readonly itemsPerPage: number;
  public readonly totalItems: number;
  public readonly totalPages: number;

  public constructor(
    currentPage: number,
    itemsPerPage: number,
    totalItems: number,
    totalPages: number,
  ) {
    this.currentPage = currentPage;
    this.itemsPerPage = itemsPerPage;
    this.totalItems = totalItems;
    this.totalPages = totalPages;
  }
}

export class PaginationLinks {
  public readonly current: string;
  public readonly first?: string;
  public readonly previous?: string;
  public readonly next?: string;
  public readonly last?: string;

  public constructor(
    current: string,
    first?: string,
    last?: string,
    previous?: string,
    next?: string,
  ) {
    this.current = current;
    if (first !== undefined) {
      this.first = first;
    }
    if (last !== undefined) {
      this.last = last;
    }
    if (previous !== undefined) {
      this.previous = previous;
    }
    if (next !== undefined) {
      this.next = next;
    }
  }
}

export class PaginatedApiResponse<T> extends ApiResponse<T[]> {
  public readonly meta: PaginationMeta;
  public readonly links: PaginationLinks;

  public constructor(data: T[], meta: PaginationMeta, links: PaginationLinks) {
    super(data);
    this.meta = meta;
    this.links = links;
  }
}
