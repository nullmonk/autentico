import { useSettings } from "./useSettings";
import type { ColumnsType, ColumnType } from "antd/es/table";

export function useHiddenColumns<T>(pagePath: string, columns: ColumnsType<T>): ColumnsType<T> {
  const { data: settings } = useSettings();

  if (!settings?.admin_ui_hidden_columns) {
    return columns;
  }

  let hiddenMap: Record<string, string[]> = {};
  try {
    hiddenMap = JSON.parse(settings.admin_ui_hidden_columns);
  } catch {
    return columns;
  }

  const hiddenForPage = hiddenMap[pagePath] || [];
  if (hiddenForPage.length === 0) {
    return columns;
  }

  const hiddenLower = hiddenForPage.map(h => h.toLowerCase());

  return columns.filter(col => {
    // Cast to access dataIndex safely
    const c = col as ColumnType<T>;
    const key = String(c.key || "").toLowerCase();
    const dataIndex = String(c.dataIndex || "").toLowerCase();
    let titleStr = "";
    if (typeof c.title === "string") {
        titleStr = c.title.toLowerCase();
    } else if (typeof c.title === "function") {
        // can't easily match function titles
    } else if (c.title && typeof (c.title as any).props?.children === "string") {
        titleStr = String((c.title as any).props.children).toLowerCase();
    }

    return !hiddenLower.some(rule => {
        return rule === key || rule === dataIndex || (titleStr && rule === titleStr);
    });
  });
}
