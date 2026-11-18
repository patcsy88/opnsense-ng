import { Card as HeroCard } from "@heroui/react";
import type * as React from "react";
import { cn } from "@/lib/utils";

export function Card(props: React.ComponentProps<typeof HeroCard>): React.ReactElement {
  return <HeroCard {...props} />;
}

export function CardHeader(props: React.ComponentProps<typeof HeroCard.Header>): React.ReactElement {
  return <HeroCard.Header {...props} />;
}

export function CardTitle(props: React.ComponentProps<typeof HeroCard.Title>): React.ReactElement {
  return <HeroCard.Title {...props} />;
}

export function CardDescription(props: React.ComponentProps<typeof HeroCard.Description>): React.ReactElement {
  return <HeroCard.Description {...props} />;
}

export function CardContent({ className, ...props }: React.ComponentProps<typeof HeroCard.Content>): React.ReactElement {
  return <HeroCard.Content className={cn(className)} {...props} />;
}

export function CardFooter(props: React.ComponentProps<typeof HeroCard.Footer>): React.ReactElement {
  return <HeroCard.Footer {...props} />;
}

export { CardContent as CardPanel };
