/**
 * TabNavigation component tests.
 *
 * Tests tab rendering, active state, and onChange callbacks.
 */
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import TabNavigation from '@/components/TabNavigation';
import type { Tab } from '@/types';

const tabs: Tab[] = [
  { id: 'tab1', label: 'First Tab' },
  { id: 'tab2', label: 'Second Tab' },
  { id: 'tab3', label: 'Third Tab' },
];

describe('TabNavigation', () => {
  it('renders all tab labels', () => {
    render(
      <TabNavigation tabs={tabs} activeTab="tab1" onChange={vi.fn()} />
    );
    expect(screen.getByText('First Tab')).toBeInTheDocument();
    expect(screen.getByText('Second Tab')).toBeInTheDocument();
    expect(screen.getByText('Third Tab')).toBeInTheDocument();
  });

  it('renders correct number of tab buttons', () => {
    render(
      <TabNavigation tabs={tabs} activeTab="tab1" onChange={vi.fn()} />
    );
    const buttons = screen.getAllByRole('button');
    expect(buttons).toHaveLength(3);
  });

  it('applies active class to selected tab', () => {
    render(
      <TabNavigation tabs={tabs} activeTab="tab2" onChange={vi.fn()} />
    );
    const secondTab = screen.getByText('Second Tab');
    expect(secondTab.className).toContain('tab-item-active');
  });

  it('does not apply active class to non-selected tabs', () => {
    render(
      <TabNavigation tabs={tabs} activeTab="tab2" onChange={vi.fn()} />
    );
    const firstTab = screen.getByText('First Tab');
    expect(firstTab.className).not.toContain('tab-item-active');
  });

  it('calls onChange with tab id when clicked', () => {
    const onChange = vi.fn();
    render(
      <TabNavigation tabs={tabs} activeTab="tab1" onChange={onChange} />
    );
    fireEvent.click(screen.getByText('Second Tab'));
    expect(onChange).toHaveBeenCalledWith('tab2');
  });

  it('calls onChange once per click', () => {
    const onChange = vi.fn();
    render(
      <TabNavigation tabs={tabs} activeTab="tab1" onChange={onChange} />
    );
    fireEvent.click(screen.getByText('Third Tab'));
    expect(onChange).toHaveBeenCalledOnce();
  });

  it('renders empty when no tabs provided', () => {
    const { container } = render(
      <TabNavigation tabs={[]} activeTab="" onChange={vi.fn()} />
    );
    expect(container.querySelector('.tab-nav')).toBeInTheDocument();
    expect(screen.queryAllByRole('button')).toHaveLength(0);
  });
});
