import css from "./Home.module.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Page not found",
  description: "The page you are looking for does not exist",
  openGraph: {
    title: "Page not found",
    description: "The page you are looking for does not exist",
    url: `https://notehub.com`,
    siteName: "NoteHub",
    images: [
      {
        url: "https://support.heberjahiz.com/hc/article_attachments/21013076295570",
        width: 1036,
        height: 683,
        alt: "NoteHub image",
      },
    ],
    type: "website",
  },
};

export default function NotFound() {
  return (
    <>
      <h1 className={css.title}>404 - Page not found</h1>
      <p className={css.description}>
        Sorry, the page you are looking for does not exist.
      </p>
    </>
  );
}
