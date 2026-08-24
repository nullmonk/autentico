import { useEffect, useRef } from "react";
import { useSettings } from "./useSettings";
import { DEFAULT_PAGE_SIZE } from "../constants/table";

function parsePageSize(value: string | undefined): number | undefined {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

// Admin-configured default page size (falls back to DEFAULT_PAGE_SIZE until
// settings have loaded, or if unset).
export function useDefaultPageSize(): number {
  const { data: settings } = useSettings();
  return parsePageSize(settings?.default_page_size) ?? DEFAULT_PAGE_SIZE;
}

// Applies the admin-configured default page size to a page's list params once
// settings load, without clobbering a page size the user has already picked.
// Returns the current default so it can also be used as the fallback in
// pagination props / handlers.
export function useApplyDefaultPageSize(setLimit: (size: number) => void): number {
  const defaultPageSize = useDefaultPageSize();
  const applied = useRef(false);
  useEffect(() => {
    if (!applied.current && defaultPageSize !== DEFAULT_PAGE_SIZE) {
      applied.current = true;
      setLimit(defaultPageSize);
    }
  }, [defaultPageSize, setLimit]);
  return defaultPageSize;
}
